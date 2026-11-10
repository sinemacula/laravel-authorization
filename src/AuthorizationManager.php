<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization;

use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Concerns\BuildsScopedManagers;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\CheckBatch;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Explanation;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException;
use SineMacula\Laravel\Authorization\Preview\Previewing;
use SineMacula\Laravel\Authorization\Query\AuthorizedQuery;
use SineMacula\Laravel\Authorization\Resolvers\GuardrailResolver;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\SessionCapResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\ActionList;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PermissionCatalogue;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;
use SineMacula\Laravel\Authorization\Usage\GrantUsageRecorder;

/**
 * Authorization manager — the facade-facing entry point.
 *
 * Coordinates subject resolution, the decision and its recording into a single
 * API (AUTHZ-9.5): `can`, `cannot`, `authorize`, `check`, `any`, `all` and
 * `explain`, over many resources at once (AUTHZ-10.3), `checkMany`, `canEach`
 * and `filterAuthorized`, on the current subject or on a scoped clone from
 * `for()`, `forUser()`, `withPolicies()` or `capped()`, or on a preview from
 * `previewFor()` (AUTHZ-11.4), which decides about another subject as the
 * caller, and the actions a subject may take in a scope, `permissionsFor`
 * (AUTHZ-10.4), decided through the same path but recording nothing. `check()`
 * is the one decision entry point (D22) and `checkMany()` the one bulk entry
 * point, `check()` deciding as `checkMany()` decides a batch of one, so a check
 * is decided the same way however it is asked: every other form adapts one of
 * them, and they alone record each decision and report it (see `CheckBatch`).
 * The decision itself is made by the manager's `DecisionPipeline`, which admits
 * the check (the subject, resource and tenant stages) and gathers every source,
 * the session caps included; the policy evaluator runs the rest of the stages
 * in AUTHZ-7.1's order, the denies, the caps, the allows and the implicit deny,
 * each recorded in the decision's trace for audit consumers. A manager from
 * `for()` of a `Subject` naming a tenant or an application decides every check,
 * batch, explanation and query scope there (N109), with the request's scope
 * restored afterwards; `permissionsFor()` lists in the scope it is given.
 *
 * `scopedTo()` is called from the `BuildsScopedManagers` trait alone, which an
 * analysis of this file by itself does not see (hence php:S1144), and so is the
 * preview the trait's `previewFor()` sets.
 *
 * @SuppressWarnings("php:S1144")
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuthorizationManager
{
    use BuildsScopedManagers, HasContainerInstance;

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
     * @param  \SineMacula\Laravel\Authorization\Usage\GrantUsageRecorder|null  $usage
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

        /** Notes the grant routes everyday checks use while grant usage is tracked; null when it is not. */
        private readonly ?GrantUsageRecorder $usage = null,
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

        // Resolved once, in the subject's scope as a check resolves it, so a
        // bound resource tenant resolver is asked once.
        $reference = $this->inSubjectScope(static fn (): false|ResourceReference|null => ResourceReferences::of($resource));

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

        // Resolved once, in the subject's scope as a check resolves it, so a
        // bound resource tenant resolver is asked once.
        $reference = $this->inSubjectScope(static fn (): false|ResourceReference|null => ResourceReferences::of($resource));

        return $list->isEveryAllowed(fn (string $action): bool => $this->check($action, $reference, $context)->isAllowed());
    }

    /**
     * Authorize the current subject for the supplied action, raising an
     * authorization exception when denied: an
     * `InsufficientAuthenticationException`, with the requirements any one of
     * which met would allow the action, when the denial is
     * `insufficient_authentication`, and an `AuthorizationException` with the
     * reason code otherwise. Either carries the decision that refused. The
     * `AuthorizationFailed` it dispatches first carries the provenance the
     * decision was recorded with, so it names the scope the decision was made
     * in, as its `DecisionEvaluated` does; when a listener has meanwhile
     * recorded another decision, it names the scope in place, or, on a preview,
     * the preview's scope and its previewer.
     *
     * On a preview from `previewFor()`, the `AuthorizationFailed` listeners run
     * as part of the preview's evaluation, so a package mutation they make is
     * refused as `administration.previewing`, and an
     * `insufficient_authentication` denial throws a plain
     * `AuthorizationException`, never `InsufficientAuthenticationException`:
     * the requirement is made of the target, which has no session, so no
     * step-up by the caller could meet it.
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
        // Resolved once, in the subject's scope as a check resolves it, so a
        // bound resource tenant resolver is asked once.
        $reference = $this->inSubjectScope(static fn (): false|ResourceReference|null => ResourceReferences::of($resource));
        $decision  = $this->check($action, $reference, $context);

        if ($decision->isAllowed()) {
            return;
        }

        $current    = fn (): DecisionProvenance => DecisionProvenance::of($this->currentSubject());
        $provenance = $this->lastDecisionStore->provenanceOf($decision) ?? $this->preview?->provenance() ?? $this->inSubjectScope($current);
        $failed     = AuthorizationFailed::of($provenance, $action, ResourceReferences::identifierOf($reference), $decision);

        if ($this->preview === null) {
            $this->events?->dispatch($failed);
        } else {
            // Its listeners run as a preview's evaluation, so they may change
            // nothing.
            Previewing::current()->during(fn (): mixed => $this->events?->dispatch($failed));
        }

        $reason = $decision->reason ?? DecisionReason::NO_MATCH;
        $stepUp = $this->preview === null && $reason === DecisionReason::INSUFFICIENT_AUTHENTICATION;
        $denial = $stepUp ? InsufficientAuthenticationException::translated($decision->requirements, $this->translator, $decision) : null;

        throw $denial ?? AuthorizationException::translated($reason, $this->translator, $decision);
    }

    /**
     * Return the further checks of the current subject, decided and gathered
     * through this manager's pipeline, its caps included, in the scope in place
     * when each is asked, or null when no subject is resolved.
     *
     * @return \SineMacula\Laravel\Authorization\Administration\FurtherChecks|null
     *
     * @internal
     */
    public function furtherChecks(): ?FurtherChecks
    {
        $subject = $this->currentSubject();

        return $subject === null ? null : $this->pipeline->furtherChecksFor($subject);
    }

    /**
     * Record and report a decision the pipeline did not make, for the current
     * subject on the action and the resource, as `check()` records and reports
     * the one it makes, then report its refusal with `AuthorizationFailed`, as
     * `authorize()` reports one, and return the `AuthorizationException` that
     * carries it: what refuses a delegated operation that conflicted on every
     * try (see `Administration\ConflictRetries`).
     *
     * @param  string  $action
     * @param  mixed  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     *
     * @internal
     */
    public function reportRefusal(string $action, mixed $resource, Decision $decision): AuthorizationException
    {
        $reference = ResourceReferences::of($resource);
        $subject   = $this->currentSubject();

        $this->batch()->recordOne($subject, new CheckInput($action, $reference), $decision);
        $this->events?->dispatch(AuthorizationFailed::of(DecisionProvenance::of($subject), $action, ResourceReferences::identifierOf($reference), $decision));

        return AuthorizationException::translated($decision->reason ?? DecisionReason::NO_MATCH, $this->translator, $decision);
    }

    /**
     * Decide the action for the current subject, the one core decision every
     * other form adapts (D22): `can()` and `cannot()` read whether it is
     * allowed, `any()` and `all()` read it for each action they decide, and
     * `authorize()` throws when it is not. It decides as `checkMany()` decides
     * a batch of one, through the same `CheckBatch`, so a check is decided the
     * same way on its own or in a batch, but reads nothing ahead and holds
     * nothing for later. The decision is recorded as the last decision and
     * reported with `DecisionEvaluated`. On a manager from `for()` of a
     * `Subject` naming a tenant or an application, it is decided there, as
     * every form adapting it is (see `for()`). On a preview from
     * `previewFor()`, the preview is admitted first, and the decision is about
     * its target, in its scope, recorded and reported with both parties.
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
        $check = new CheckInput($action, $resource, $context);

        if ($this->preview !== null) {
            return $this->preview->run(fn (?Subject $target): Decision => $this->batch()->decideOne($target, $check));
        }

        return $this->inSubjectScope(fn (): Decision => $this->batch()->decideOne($this->currentSubject(), $check));
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
     * is decided, when one is not a `CheckInput`. On a preview, the preview is
     * admitted once for the batch, before any check is decided.
     *
     * @template TKey of array-key
     *
     * @param  array<TKey, \SineMacula\Laravel\Authorization\Evaluation\CheckInput>  $checks
     * @return array<TKey, \SineMacula\Laravel\Authorization\Evaluation\Decision>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     *
     * @phpstan-ignore throws.unusedType, throws.unusedType
     */
    public function checkMany(array $checks): array
    {
        if ($this->preview !== null) {
            return $this->preview->run(fn (?Subject $target): array => $this->batch()->decide($target, $checks));
        }

        return $this->inSubjectScope(fn (): array => $this->batch()->decide($this->currentSubject(), $checks));
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
     * On a preview, each compile, now and at each execution, admits the preview
     * again, in every scope its classes of rows are decided in, recorded as its
     * admission is, and compiles for its target in its scope; and the scope
     * refuses its own writes: an update, a delete or an insert from the query,
     * or from one nesting it whole, is refused (`preview_write`), though one
     * taking it in as SQL text is not (see `AuthorizedQuery`). The rows it
     * keeps are those the target may take the action on, which is no proof the
     * caller may see them.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $action
     * @param  array<string, mixed>  $context
     * @return \SineMacula\Laravel\Authorization\Query\AuthorizedQuery
     */
    public function queryScope(Model $model, string $action, array $context = []): AuthorizedQuery
    {
        $authorizer = $this->pipeline->queryAuthorizer();
        $preview    = $this->preview;
        $compile    = static fn (?Subject $subject): string => $authorizer->compile($subject, $model, $action, $context);

        if ($preview !== null) {
            return AuthorizedQuery::compiled($model, $action, static fn (): string => $preview->run($compile), true);
        }

        return AuthorizedQuery::compiled($model, $action, fn (): string => $this->inSubjectScope(fn (): string => $compile($this->currentSubject())));
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
     * Return the provenance of the decision `lastDecision()` returns: who it
     * was about, as references to the principal and its identity, who previewed
     * it, for a preview, and the tenant and application it was made in (see
     * `DecisionProvenance`). Null whenever `lastDecision()` is.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance|null
     */
    public function lastDecisionProvenance(): ?DecisionProvenance
    {
        return $this->lastDecision() === null ? null : $this->lastDecisionStore->provenance();
    }

    /**
     * Decide the supplied action in explain mode and return the decision's
     * explanation (AUTHZ-11.5, N89): the verdict, the statements, or the cap or
     * permission, that decided it, every condition test of every stage it
     * reached with what it found, the keys found missing, the stages it never
     * reached, where each grant that allowed it came from, and what the check
     * asked (see `Explanation`). The check is the one `check()` makes, through
     * the same path and the same stages, so its verdict is the same, and it is
     * recorded as the last decision and reported as any check is; explain mode
     * only records the evidence besides. On a preview, the preview is admitted
     * as for `check()`, and the right to preview discloses the target's
     * explanation (N85), which names statements, conditions, caps and
     * requirements, never a value or a session; a refused preview explains
     * nothing.
     *
     * @param  string  $action
     * @param  mixed  $resource
     * @param  array<string, mixed>  $context
     * @return \SineMacula\Laravel\Authorization\Evaluation\Explanation
     */
    public function explain(string $action, mixed $resource = null, array $context = []): Explanation
    {
        $check   = new CheckInput($action, $resource, $context);
        $explain = fn (?Subject $target): Decision => $this->batch(isExplaining: true)->decideOne($target, $check);

        return ($this->preview === null ? $this->inSubjectScope(fn (): Decision => $explain($this->currentSubject())) : $this->preview->run($explain))->explain();
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
     * Return the actions the subject may take in the scope (AUTHZ-10.4, N69),
     * for a UI to show or hide its controls: every action the permission
     * catalogue declares (the package's own permissions, the cases of the
     * configured enums and the definitions of the configured providers), each
     * name once, in the catalogue's order, whose `check()` on the scope's
     * resource, with the context, would allow, in the scope, about the subject.
     *
     * A resolved `Subject` is taken as it is, its identity, guard and session
     * kept; any other object is named as `for()` names it; and null is the
     * subject this manager's checks are about, as `check()` takes it: the
     * request's, or the one `for()` or `forUser()` named, so
     * `forUser(null)->permissionsFor(null, ...)` lists a guest's actions, which
     * are none. The scope's tenant and application are put in place of the
     * request's, both as the subject's and as the scope of the grants that
     * count, and the request's are restored once the actions are decided, even
     * when deciding one throws, with what the resolution cache held for them
     * (see `AuthorizationScope`). The scope given wins over the one a `Subject`
     * named through `for()` would decide in, as it does inside
     * `AuthorizationScope::within()`.
     *
     * The listing is exact: each action is decided through the one decision
     * path `checkMany()` takes, over what the checks share read once, the
     * resource's tenant and attributes among it, so its denies, conditions,
     * boundaries, guardrails, caps and authentication requirements are weighed
     * exactly as `check()` weighs them, never as the allows less the denies. An
     * action whose check would be `insufficient_authentication` is not listed,
     * and one whose check would throw makes the listing throw what it throws,
     * so nothing is ever listed that the check would not allow. A listing for
     * one resource can differ from a listing for none, and the action is still
     * to be authorized when it is taken.
     *
     * Listing is introspection, not a check (N70): it records no last decision
     * and dispatches no `DecisionEvaluated` and no `AuthorizationFailed`. The
     * break-glass reporting of BL-70 is to define how it treats it. A catalogue
     * that cannot be read, such as one declaring a name twice with different
     * metadata, throws `InvalidPermissionCatalogueException`.
     *
     * On a preview from `previewFor()`, the subject is the preview's target,
     * named by null alone: naming any subject, or a scope of another tenant or
     * application than the preview's, throws `InvalidPreviewException`. The
     * preview is admitted first, and every action it evaluates dispatches its
     * `DecisionEvaluated`, naming both parties, while the last decision is left
     * as the admission recorded it (N86).
     *
     * @param  object|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope  $scope
     * @param  array<string, mixed>  $context
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException
     *
     * @phpstan-ignore throws.unusedType
     */
    public function permissionsFor(?object $subject, AuthorizationScope $scope, array $context = []): array
    {
        $preview = $this->preview;

        if ($subject !== null && $preview !== null) {
            throw InvalidPreviewException::retargeted('permissionsFor');
        }

        $named = match (true) {
            $subject === null           => $this->currentSubject(),
            $subject instanceof Subject => $subject,
            default                     => $this->for($subject)->currentSubject(),
        };

        $preview?->refuseOtherScope($scope);

        /** @var \SineMacula\Laravel\Authorization\Support\PermissionCatalogue $catalogue */
        $catalogue = Container::getInstance()->make(PermissionCatalogue::class);
        $actions   = \array_unique(\array_map(static fn (PermissionDefinition $definition): string => $definition->name, $catalogue->definitions()));

        $list = fn (?Subject $about): array => $scope->within(function () use ($about, $scope, $actions, $context, $preview): array {
            // Every action is decided on the one reference, so the resource is
            // told, and its attributes read, once for the listing.
            $resource  = ResourceReferences::of($scope->resource);
            $checks    = \array_map(static fn (string $action): CheckInput => new CheckInput($action, $resource, $context), $actions);
            $decisions = $this->batch($preview !== null, false)->decide($about, $checks);

            return \array_values(\array_filter($actions, static fn (int $key): bool => $decisions[$key]->isAllowed(), \ARRAY_FILTER_USE_KEY));
        });

        // A preview's target is already the subject of its scope, which is the
        // listing's.
        return $preview === null ? $list($scope->subjectIn($named)) : $preview->run($list);
    }

    /**
     * Report a change to the application's tenant tree at the tenant: it moved
     * under another parent, or was deleted (AUTHZ-12.8).
     *
     * Every resolution built in the tenant or below it is dropped, in every
     * worker, and the current tenant's ancestors are read afresh, so a moved
     * tenant never keeps grants inherited from its old ancestors. A delegated
     * administration call running meanwhile is tried again rather than written
     * on the chains its decisions read (see `OperationScope::treeChanged()`). A
     * failure of the cache store is thrown, so the caller can retry.
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

        OperationScope::treeChanged();
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

    /**
     * Return the batch that decides this manager's checks, through its
     * pipeline, so `check()`, `checkMany()` and `permissionsFor()` take the one
     * path, dispatching each decision's event and storing it as the last
     * decision, or, for introspection, neither, or, for a preview's listing,
     * dispatching alone; a preview's decisions name its previewer. The batch
     * `explain()` decides through explains its check.
     *
     * While grant usage is tracked, an everyday check's batch decides through a
     * pipeline that notes the grant routes each decision used (N100); a
     * preview's, an explanation's and a listing's never do (N70, N86, N89),
     * since none of them is a decision the application acts on.
     *
     * @param  bool  $isDispatching
     * @param  bool  $isStoring
     * @param  bool  $isExplaining
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckBatch
     */
    private function batch(bool $isDispatching = true, bool $isStoring = true, bool $isExplaining = false): CheckBatch
    {
        $usage = $this->usage !== null && $isStoring && !$isExplaining && $this->preview === null ? $this->usage : null;

        return new CheckBatch(
            $usage === null ? $this->pipeline : $this->pipeline->tracking($usage),
            $this->lastDecisionStore,
            $this->subjectResolver,
            $this->events,
            $isDispatching,
            $isStoring,
            $this->preview?->previewer,
            $isExplaining,
        );
    }
}
