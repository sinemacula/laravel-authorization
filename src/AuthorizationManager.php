<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Context\AttributeNamespaces;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;
use SineMacula\Laravel\Authorization\Support\ResourceScope;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;

/**
 * Authorization manager — the facade-facing entry point.
 *
 * Coordinates subject resolution, policy gathering, evaluation, and RBAC
 * fallback into a single API. The manager is deliberately small and delegates
 * the actual statement walking to the policy evaluator; every stage returns a
 * decision, with the reason code and trace recorded for audit consumers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuthorizationManager
{
    use HasContainerInstance;

    /** @var \SineMacula\Laravel\Authorization\Subject|null The subject named through `for()` or `forUser()`; null defers to the bound resolver. */
    private ?Subject $subjectOverride = null;

    /** @var array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>|null  Per-call policy override supplied via `withPolicies()`. */
    private ?array $policyOverride = null;

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
     */
    public function __construct(

        /** Policy evaluator used to walk statements for every check. */
        private readonly PolicyEvaluator $evaluator,

        /** Resolves the subject, tenant and application of the current request. */
        private readonly SubjectResolver $subjectResolver,

        /** Gathers the policy set applicable to a principal per check. */
        private readonly PolicyResolver $policyResolver,

        /** Shared single-slot store holding the last evaluation result. */
        private readonly LastDecisionStore $lastDecisionStore,

        /** Event dispatcher used to emit decision events; null disables. */
        private readonly ?Dispatcher $events = null,

        /** Translator that words a denial's message; null keeps English. */
        private readonly ?Translator $translator = null,

        /** Makes each check's context from its sources; null gives a check only what the caller passes, under `input`. */
        private readonly ?CheckContextFactory $contexts = null,
    ) {}

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

        $this->dispatch(new AuthorizationFailed($this->currentSubject()?->subject, $action, self::identifierOf($reference), $context, $decision));

        $reason = $decision->reason ?? DecisionReason::NO_MATCH;
        $denial = $reason === DecisionReason::INSUFFICIENT_AUTHENTICATION ? InsufficientAuthenticationException::translated($decision->requirements, $this->translator) : null;

        throw $denial ?? AuthorizationException::translated($reason, $this->translator);
    }

    /**
     * Decide the action for the current subject, the one core decision every
     * other form adapts (D22): `can()` reads whether it is allowed and
     * `authorize()` throws when it is not. The decision is recorded as the last
     * decision and reported with `DecisionEvaluated`.
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
        $subject   = $this->currentSubject();
        $reference = ResourceReferences::of($resource);

        return $this->record($subject, $action, self::identifierOf($reference), $context, $this->decide($subject, $action, $reference, $context));
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
     * Return a scoped manager deciding about the supplied subject.
     *
     * The decisions keep the current request's tenant, application and guard,
     * as the resolver reports them; with no subject resolved, they have none.
     *
     * @param  object  $subject
     * @return self
     */
    public function for(object $subject): self
    {
        return $this->scopedTo($this->currentSubject()?->withSubject($subject) ?? new Subject($subject, $subject));
    }

    /**
     * Return a scoped manager deciding about the subject the resolver
     * translates the supplied user into: the user Laravel's Gate hands over,
     * for example.
     *
     * @param  object  $user
     * @return self
     */
    public function forUser(object $user): self
    {
        return $this->scopedTo($this->subjectResolver->forUser($user));
    }

    /**
     * Return a scoped manager that evaluates only the supplied policies,
     * bypassing the principal's own attached policies and any configured policy
     * store.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return self
     */
    public function withPolicies(array $policies): self
    {
        $scoped                 = clone $this;
        $scoped->policyOverride = \array_values($policies);

        return $scoped;
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
     * Honours a `for()` or `forUser()` scope when active; otherwise defers to
     * the bound `SubjectResolver`. Public so every surface that needs the
     * current subject — middleware, Blade helpers, custom Gates — can delegate
     * here instead of re-implementing the scope and resolver pair.
     *
     * @return \SineMacula\Laravel\Authorization\Subject|null
     */
    public function currentSubject(): ?Subject
    {
        return $this->subjectOverride ?? $this->subjectResolver->resolve();
    }

    /**
     * Return a clone of this manager deciding about the supplied subject.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return self
     */
    private function scopedTo(Subject $subject): self
    {
        $scoped                  = clone $this;
        $scoped->subjectOverride = $subject;

        return $scoped;
    }

    /**
     * Decide the action for the supplied subject, stage by stage (AUTHZ-7.1): a
     * subject that is missing, or inactive (it or its identity), is denied
     * before anything else is read; a resource that cannot be identified is
     * denied next; a tenant-owned resource is decided in its tenant's scope, or
     * denied as out of scope (see `ResourceScope`); then the grants decide.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  string  $action
     * @param  false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @param  array<string, mixed>  $context
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private function decide(?Subject $subject, string $action, false|ResourceReference|null $resource, array $context): Decision
    {
        if ($subject === null || SubjectGrants::isInactive($subject)) {
            return Decision::deny($subject === null ? DecisionReason::SUBJECT_UNRESOLVED : DecisionReason::SUBJECT_INACTIVE, DecisionStage::SUBJECT);
        }

        if ($resource === false) {
            return Decision::deny(DecisionReason::RESOURCE_UNRESOLVED, DecisionStage::RESOURCE);
        }

        $decide = fn (): Decision => $this->decideGrants($subject, $action, $resource, $context);

        return $resource === null ? $decide() : ResourceScope::decide($subject, $action, $resource, $decide);
    }

    /**
     * Decide the action from the subject's grants: its policies' statements,
     * and its identity's, by their deny and allow stages, then, when they allow
     * nothing, a permission the subject holds. A policy document that cannot be
     * read denies the check as an invalid policy. The subject's identity, when
     * it is another model, contributes its policies and its grants (see
     * `SubjectGrants`).
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @param  array<string, mixed>  $context
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private function decideGrants(Subject $subject, string $action, ?ResourceReference $resource, array $context): Decision
    {
        try {
            $policies = $this->gatherPolicies($subject);
        } catch (InvalidPolicyDocumentException) {
            return Decision::deny(DecisionReason::INVALID_POLICY, DecisionStage::DENY);
        }

        // What the caller passes is held under `input` alone, never promoted
        // into another namespace, so it cannot stand in for the request, the
        // authentication, the subject, the resource or any source's values
        // (N27). Without a factory, the subject and resource still supply their
        // built-in keys.
        $checkContext = $this->contexts?->make($context, $subject, $resource)
            ?? new CheckContext([CheckContextFactory::INPUT => $context], (new AttributeNamespaces)->builders($subject, $resource));
        $decision = $this->evaluator->evaluate($policies, $action, $resource?->identifier, $checkContext);

        return $decision->stage === DecisionStage::IMPLICIT ? $decision->withPermission(SubjectGrants::holdsPermission($subject, $action)) : $decision;
    }

    /**
     * Return the identifier a resolved reference carries, or null for no
     * resource or one that cannot be identified.
     *
     * @param  false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null  $reference
     * @return string|null
     */
    private static function identifierOf(false|ResourceReference|null $reference): ?string
    {
        return $reference === false ? null : $reference?->identifier;
    }

    /**
     * Gather the policies applicable to the supplied subject.
     *
     * When a per-call override is in effect, it is returned verbatim. Otherwise
     * the manager delegates to the bound `PolicyResolver` for the subject —
     * consumers swap the resolver to introduce tenant scoping or other
     * gathering strategies without touching the manager — and adds the policies
     * attached to its identity when that is another model.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private function gatherPolicies(Subject $subject): array
    {
        if ($this->policyOverride !== null) {
            return $this->policyOverride;
        }

        return [...$this->policyResolver->policiesFor($subject->subject), ...SubjectGrants::identityPolicies($subject)];
    }

    /**
     * Record the result as the last decision, with the session of the request
     * when it read an authentication requirement, and dispatch its decision
     * event.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private function record(?Subject $subject, string $action, ?string $resource, array $context, Decision $decision): Decision
    {
        $this->lastDecisionStore->put($decision, $decision->freshness === null ? null : $this->subjectResolver->resolve()?->session);
        $this->dispatch(new DecisionEvaluated($subject?->subject, $action, $resource, $context, $decision));

        return $decision;
    }

    /**
     * Dispatch the supplied event when a dispatcher is available.
     *
     * @param  object  $event
     * @return void
     */
    private function dispatch(object $event): void
    {
        $this->events?->dispatch($event);
    }
}
