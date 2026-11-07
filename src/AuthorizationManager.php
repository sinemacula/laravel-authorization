<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Concerns\BuildsScopedManagers;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\CheckBatch;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Authorization\Query\AuthorizedQuery;
use SineMacula\Laravel\Authorization\Resolvers\GuardrailResolver;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\SessionCapResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\ActionList;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;

/**
 * Authorization manager — the facade-facing entry point.
 *
 * Coordinates subject resolution, the decision and its recording into a single
 * API (AUTHZ-9.5): `can`, `cannot`, `authorize`, `check`, `any`, `all` and
 * `explain`, and, over many resources at once (AUTHZ-10.3), `checkMany`,
 * `canEach` and `filterAuthorized`, on the current subject or on a scoped clone
 * from `for()`, `forUser()`, `withPolicies()` or `capped()`. `check()` is the
 * one decision entry point (D22) and `checkMany()` the one bulk entry point,
 * `check()` being a batch of one, so a check is decided the same way however it
 * is asked: every other form adapts one of them, and they alone record each
 * decision and report it (see `CheckBatch`). The decision itself is made by the
 * manager's `DecisionPipeline`, which admits the check (the subject, resource
 * and tenant stages) and gathers every source, the session caps included; the
 * policy evaluator runs the rest of the stages in AUTHZ-7.1's order, the
 * denies, the caps, the allows and the implicit deny, each recorded in the
 * decision's trace for audit consumers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuthorizationManager
{
    use BuildsScopedManagers, HasContainerInstance;

    /** @var \SineMacula\Laravel\Authorization\Subject|null The subject named through `for()` or `forUser()`, null for a guest. */
    private ?Subject $subjectOverride = null;

    /** @var bool Whether `for()` or `forUser()` named the subject; until one does, the bound resolver resolves it. */
    private bool $isSubjectNamed = false;

    /** @var \SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline Decides each check, with the policy override and the caps of this scope. */
    private DecisionPipeline $pipeline;

    /**
     * Create a new manager instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator  $evaluator
     * @param  \SineMacula\Laravel\Authorization\Contracts\SubjectResolver  $subjectResolver
     * @param  \SineMacula\Laravel\Authorization\Contracts\PolicyResolver  $policyResolver
     * @param  \SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore  $lastDecisionStore
     * @param  \Illuminate\Contracts\Events\Dispatcher|null  $events
     * @param  \Illuminate\Contracts\Translation\Translator|null  $translator
     * @param  \SineMacula\Laravel\Authorization\Context\CheckContextFactory|null  $contexts
     * @param  \SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver|null  $resourcePolicies
     * @param  \SineMacula\Laravel\Authorization\Resolvers\GuardrailResolver|null  $guardrails
     * @param  \SineMacula\Laravel\Authorization\Resolvers\SessionCapResolver|null  $sessionCaps
     */
    public function __construct(

        // Policy evaluator used to walk statements for every check.
        PolicyEvaluator $evaluator,

        /** Resolves the subject, tenant and application of the current request. */
        private readonly SubjectResolver $subjectResolver,

        // Gathers the policy set applicable to a principal per check.
        PolicyResolver $policyResolver,

        /** Shared single-slot store holding the last evaluation result. */
        private readonly LastDecisionStore $lastDecisionStore,

        /** Event dispatcher used to emit decision events; null disables. */
        private readonly ?Dispatcher $events = null,

        /** Translator that words a denial's message; null keeps English. */
        private readonly ?Translator $translator = null,

        // Makes each check's context from its sources; null gives a check only
        // what the caller passes, under `input`.
        ?CheckContextFactory $contexts = null,

        // Reads the policies attached to a check's resource and its type; null
        // reads none.
        ?ResourcePolicyResolver $resourcePolicies = null,

        // Reads the guardrails that apply to a check; null reads none.
        ?GuardrailResolver $guardrails = null,

        // Makes the session caps of a check; null reads no credential's scopes,
        // so only `capped()` and a machine's missing scopes cap it.
        ?SessionCapResolver $sessionCaps = null,
    ) {
        $this->pipeline = new DecisionPipeline($evaluator, $policyResolver, $contexts, $resourcePolicies, $guardrails, $sessionCaps);
    }

    /**
     * Determine whether the current subject is allowed to perform the supplied
     * action.
     *
     * @param  string  $action
     * @param  mixed  $resource
     * @param  array<string, mixed>  $context
     * @return bool
     */
    public function can(string $action, mixed $resource = null, array $context = []): bool
    {
        return $this->check($action, $resource, $context)->isAllowed();
    }

    /**
     * Determine whether the current subject is refused the supplied action: the
     * negation of `can()`, so an `insufficient_authentication` decision is a
     * refusal too. The decision is recorded as `check()` records it.
     *
     * @param  string  $action
     * @param  mixed  $resource
     * @param  array<string, mixed>  $context
     * @return bool
     */
    public function cannot(string $action, mixed $resource = null, array $context = []): bool // phpcs:ignore SineMacula.NamingConventions.BooleanMethodName.NotPredicate
    {
        return !$this->can($action, $resource, $context);
    }

    /**
     * Determine whether the current subject is allowed any of the supplied
     * actions on the resource.
     *
     * Each action is decided through `check()`, in the order given, and the
     * first allow answers: no action after it is decided. Every decision made
     * is recorded and reported as `check()` records it, so the last decision is
     * that of the last action decided. An `insufficient_authentication`
     * decision is a refusal. A list naming no action is refused before any is
     * decided.
     *
     * @param  array<int, string>  $actions
     * @param  mixed  $resource
     * @param  array<string, mixed>  $context
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public function any(array $actions, mixed $resource = null, array $context = []): bool // phpcs:ignore SineMacula.NamingConventions.BooleanMethodName.NotPredicate
    {
        $list = ActionList::of('any', $actions);

        // Resolved once, so a bound resource tenant resolver is asked once.
        $reference = ResourceReferences::of($resource);

        return $list->isAnyAllowed(fn (string $action): bool => $this->check($action, $reference, $context)->isAllowed());
    }

    /**
     * Determine whether the current subject is allowed every one of the
     * supplied actions on the resource.
     *
     * Each action is decided through `check()`, in the order given, and the
     * first refusal answers: no action after it is decided. Every decision made
     * is recorded and reported as `check()` records it, so the last decision is
     * that of the last action decided. An `insufficient_authentication`
     * decision is a refusal. A list naming no action is refused before any is
     * decided.
     *
     * @param  array<int, string>  $actions
     * @param  mixed  $resource
     * @param  array<string, mixed>  $context
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public function all(array $actions, mixed $resource = null, array $context = []): bool // phpcs:ignore SineMacula.NamingConventions.BooleanMethodName.NotPredicate
    {
        $list = ActionList::of('all', $actions);

        // Resolved once, so a bound resource tenant resolver is asked once.
        $reference = ResourceReferences::of($resource);

        return $list->isEveryAllowed(fn (string $action): bool => $this->check($action, $reference, $context)->isAllowed());
    }

    /**
     * Authorize the current subject for the supplied action, raising an
     * authorization exception when denied: an
     * `InsufficientAuthenticationException`, with the requirements any one of
     * which met would allow the action, when the denial is
     * `insufficient_authentication`, and an `AuthorizationException` with the
     * reason code otherwise.
     *
     * @param  string  $action
     * @param  mixed  $resource
     * @param  array<string, mixed>  $context
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function authorize(string $action, mixed $resource = null, array $context = []): void
    {
        // Resolved once, so a bound resource tenant resolver is asked once.
        $reference = ResourceReferences::of($resource);
        $decision  = $this->check($action, $reference, $context);

        if ($decision->isAllowed()) {
            return;
        }

        $this->events?->dispatch(new AuthorizationFailed($this->currentSubject()?->subject, $action, ResourceReferences::identifierOf($reference), $context, $decision));

        $reason = $decision->reason ?? DecisionReason::NO_MATCH;
        $denial = $reason === DecisionReason::INSUFFICIENT_AUTHENTICATION ? InsufficientAuthenticationException::translated($decision->requirements, $this->translator) : null;

        throw $denial ?? AuthorizationException::translated($reason, $this->translator);
    }

    /**
     * Decide the action for the current subject, the one core decision every
     * other form adapts (D22): `can()` and `cannot()` read whether it is
     * allowed, `any()` and `all()` read it for each action they decide, and
     * `authorize()` throws when it is not. It is `checkMany()` given one check,
     * so a check is decided the same way on its own or in a batch. The decision
     * is recorded as the last decision and reported with `DecisionEvaluated`.
     *
     * The context is what the caller passes, which a policy reads under `input`
     * (`['post' => ['status' => 'draft']]` is `input.post.status`) and never
     * anywhere else: the `authentication`, `request` and `environment`
     * namespaces, and those the application's sources add, come from their
     * sources alone, and `subject` and `resource` from the check's subject and
     * resource and their attribute providers, each built only when a statement
     * of the check reads it. A model given as the resource is handed to its
     * type's resource attribute provider. A provider that fails aborts the
     * check with `AttributeProviderFailed`: no decision is recorded or
     * reported.
     *
     * @param  string  $action
     * @param  mixed  $resource
     * @param  array<string, mixed>  $context
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed
     *
     * @phpstan-ignore throws.unusedType
     */
    public function check(string $action, mixed $resource = null, array $context = []): Decision
    {
        return $this->checkMany([new CheckInput($action, $resource, $context)])[0];
    }

    /**
     * Decide each of the checks for the current subject, the one core bulk
     * decision (D22, AUTHZ-10.3), and return the decisions keyed as the checks
     * are, in their order, one for every check, a check repeated included.
     *
     * Each check is decided exactly as `check()` decides it, through the same
     * stages, so its decision is the one `check()` would make, but what the
     * checks share is read once: the subject, and what its grants, policies,
     * boundaries, caps and the guardrails resolve to, once in each scope the
     * checks are decided in, and the tenants, attached policies and attributes
     * of the resources in bulk, a chunk of `authorization.bulk.chunk_size` at a
     * time (see `CheckBatch`). Each decision is recorded as the last decision
     * and reported with its own `DecisionEvaluated` as soon as it is made, in
     * the order of the checks, so the last decision is the last check
     * completed, and an empty list records nothing. A check that throws, as
     * `check()` would, stops the batch there, the checks before it recorded.
     * Every check is refused with `InvalidCheckArgumentException`, before any
     * is decided, when one is not a `CheckInput`.
     *
     * @template TKey of array-key
     *
     * @param  array<TKey, \SineMacula\Laravel\Authorization\Evaluation\CheckInput>  $checks
     * @return array<TKey, \SineMacula\Laravel\Authorization\Evaluation\Decision>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     *
     * @phpstan-ignore throws.unusedType
     */
    public function checkMany(array $checks): array
    {
        return (new CheckBatch($this->pipeline, $this->lastDecisionStore, $this->subjectResolver, $this->events))->decide($this->currentSubject(), $checks);
    }

    /**
     * Determine, for each resource, whether the current subject is allowed the
     * action on it, keyed as the resources are, through `checkMany()`: every
     * resource is decided, none stopping the rest, and recorded and reported as
     * `check()` records it. An `insufficient_authentication` decision is a
     * refusal. No resource gives none.
     *
     * @template TKey of array-key
     *
     * @param  string  $action
     * @param  iterable<TKey, mixed>  $resources
     * @param  array<string, mixed>  $context
     * @return array<TKey, bool>
     */
    public function canEach(string $action, iterable $resources, array $context = []): array
    {
        $checks = [];

        foreach ($resources as $key => $resource) {
            $checks[$key] = new CheckInput($action, $resource, $context);
        }

        return \array_map(static fn (Decision $decision): bool => $decision->isAllowed(), $this->checkMany($checks));
    }

    /**
     * Return the resources the current subject is allowed the action on, with
     * their keys, in their order, as given, through `canEach()`: a collection
     * of the same class for a collection, else an array. Every resource is
     * decided, none stopping the rest, and recorded and reported as `check()`
     * records it. An `insufficient_authentication` decision is a refusal. No
     * resource gives none.
     *
     * @param  string  $action
     * @param  iterable<array-key, mixed>  $resources
     * @param  array<string, mixed>  $context
     * @return ($resources is \Illuminate\Support\Collection<array-key, mixed> ? \Illuminate\Support\Collection<array-key, mixed> : array<array-key, mixed>)
     */
    public function filterAuthorized(string $action, iterable $resources, array $context = []): array|Collection
    {
        if ($resources instanceof Collection) {
            $allowed = $this->canEach($action, $resources->all(), $context);

            return $resources->filter(static fn (mixed $resource, int|string $key): bool => $allowed[$key]);
        }

        $items   = \is_array($resources) ? $resources : \iterator_to_array($resources);
        $allowed = $this->canEach($action, $items, $context);

        return \array_filter($items, static fn (int|string $key): bool => $allowed[$key], \ARRAY_FILTER_USE_KEY);
    }

    /**
     * Return the scope that keeps the rows of the model's queries the current
     * subject may take the action on, with the caller's context, as `check()`
     * decides them (AUTHZ-10.1): `whereAuthorized()` puts it on a builder.
     *
     * It is compiled now, so a query the scope cannot compile exactly is
     * refused here with `QueryScopeRefusedException`, and compiled again from
     * the state at each execution, about the subject current then. Compiling
     * decides no check: no decision is recorded and no decision event is
     * dispatched.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $action
     * @param  array<string, mixed>  $context
     * @return \SineMacula\Laravel\Authorization\Query\AuthorizedQuery
     */
    public function queryScope(Model $model, string $action, array $context = []): AuthorizedQuery
    {
        $authorizer = $this->pipeline->queryAuthorizer();

        return AuthorizedQuery::compiled($model, $action, fn (): string => $authorizer->compile($this->currentSubject(), $model, $action, $context));
    }

    /**
     * Return the most recent decision produced by this process — across every
     * scoped clone and Gate-dispatched path. Request-layer error handlers use
     * this to answer "why was the last check denied?" without re-running the
     * evaluation.
     *
     * Returns null when the process has not yet produced a decision or when the
     * store was explicitly cleared between requests in a long-running worker. A
     * decision that read an authentication requirement is returned only in the
     * session of the request that recorded it, as the subject resolver gives
     * it, whichever subject the decision was about (one named with `for()`
     * included), and until the earliest instant a met requirement it read stops
     * being met (N37).
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision|null
     */
    public function lastDecision(): ?Decision
    {
        $decision = $this->lastDecisionStore->get();

        return $decision?->freshness === null || $this->lastDecisionStore->wasRecordedIn($this->subjectResolver->resolve()?->session) ? $decision : null;
    }

    /**
     * Decide the supplied action and return the decision's explanation: the
     * verdict, the stage and statements that decided it, each requirement an
     * insufficient authentication names with its unmet parts, and every step of
     * its trace. A shortcut over `check(...)->explain()`.
     *
     * @param  string  $action
     * @param  mixed  $resource
     * @param  array<string, mixed>  $context
     * @return string
     */
    public function explain(string $action, mixed $resource = null, array $context = []): string
    {
        return $this->check($action, $resource, $context)->explain();
    }

    /**
     * Clear the recorded last decision. Long-running workers call this between
     * requests so a stale decision does not leak across the request boundary.
     *
     * @return void
     */
    public function forgetLastDecision(): void
    {
        $this->lastDecisionStore->forget();
    }

    /**
     * Return a map of every registered permission to its effective decision for
     * the current subject.
     *
     * Walks every case of every configured `PermissionEnum` and decides each
     * through the full decision. The result is an associative array keyed by
     * permission string with boolean values indicating whether the subject is
     * allowed.
     *
     * Performance note: this method performs N evaluations where N is the total
     * number of registered enum cases. Callers should cache the result when
     * rendering permission-picker UIs or capability checklists rather than
     * calling this on every request.
     *
     * @param  array<string, mixed>  $context
     * @return array<string, bool>
     */
    public function effectivePermissions(array $context = []): array
    {
        /** @var array<int, mixed> $enums */
        $enums = \function_exists('config')
            ? (array) config('authorization.permission_enums', [])
            : []; // @codeCoverageIgnore

        $permissions = [];

        foreach ($enums as $enumClass) {
            if (!ConfigValidator::isStringBackedPermissionEnum($enumClass)) {
                continue;
            }

            /** @var class-string<\SineMacula\Laravel\Authorization\Contracts\PermissionEnum> $className */
            $className = $enumClass;

            foreach ($className::cases() as $case) {
                // Only enums backed by strings get this far.
                /** @var string $action */
                $action               = $case->value;
                $permissions[$action] = $this->can($action, null, $context);
            }
        }

        return $permissions;
    }

    /**
     * Report a change to the application's tenant tree at the tenant: it moved
     * under another parent, or was deleted (AUTHZ-12.8).
     *
     * Every resolution built in the tenant or below it is dropped, in every
     * worker, and the current tenant's ancestors are read afresh, so a moved
     * tenant never keeps grants inherited from its old ancestors. A failure of
     * the cache store is thrown, so the caller can retry.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant|\SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    public function treeChanged(AuthorizableTenant|Model|Reference $tenant): void
    {
        $reference = $tenant instanceof Reference ? $tenant : new Reference(...TenantScope::extractTenantPair($tenant));

        ResolutionCache::instance()?->treeChanged($reference);

        (new TenantScope)->flushResolvedTenant();
    }

    /**
     * Resolve the subject in scope for this invocation.
     *
     * Honours a `for()` or `forUser()` scope when active, a guest's being no
     * subject; otherwise defers to the bound `SubjectResolver`. Public so every
     * surface that needs the current subject — middleware, Blade helpers,
     * custom Gates — can delegate here instead of re-implementing the scope and
     * resolver pair.
     *
     * @return \SineMacula\Laravel\Authorization\Subject|null
     */
    public function currentSubject(): ?Subject
    {
        return $this->isSubjectNamed ? $this->subjectOverride : $this->subjectResolver->resolve();
    }
}
