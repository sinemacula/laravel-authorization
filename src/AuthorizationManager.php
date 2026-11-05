<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Translation\Translator;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\EvaluationResult;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;

/**
 * Authorization manager — the facade-facing entry point.
 *
 * Coordinates subject resolution, policy gathering, evaluation, and RBAC
 * fallback into a single API. The manager is deliberately small and delegates
 * the actual statement walking to the policy evaluator; all four evaluation
 * branches ultimately return an evaluation result, with the reason code and
 * trace recorded for audit consumers.
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
    ) {}

    /**
     * Determine whether the current subject is allowed to perform the supplied
     * action.
     *
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return bool
     */
    public function can(string $action, ?string $resource = null, array $context = []): bool
    {
        return $this->evaluate($action, $resource, $context)->allowed;
    }

    /**
     * Authorize the current subject for the supplied action, raising an
     * authorization exception when denied.
     *
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function authorize(string $action, ?string $resource = null, array $context = []): void
    {
        $subject = $this->currentSubject();
        $result  = $this->evaluateFor($subject, $action, $resource, $context);

        $this->lastDecisionStore->put($result);
        $this->dispatch(new DecisionEvaluated($subject?->subject, $action, $resource, $context, $result));

        if (!$result->allowed) {
            $this->dispatch(new AuthorizationFailed($subject?->subject, $action, $resource, $context, $result));

            throw AuthorizationException::translated($result->reason, $this->translator);
        }
    }

    /**
     * Evaluate the supplied action for the current subject and return the full
     * evaluation result.
     *
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult
     */
    public function evaluate(string $action, ?string $resource = null, array $context = []): EvaluationResult
    {
        $subject = $this->currentSubject();

        return $this->record($subject, $action, $resource, $context, $this->evaluateFor($subject, $action, $resource, $context));
    }

    /**
     * Deny a check whose resource argument could not be identified (an unsaved
     * model, a number, a list), recording the denial and dispatching the
     * decision event as any other check does.
     *
     * The Gate calls this instead of evaluating a check without a resource,
     * which a statement covering every resource would otherwise allow.
     *
     * @param  string  $action
     * @param  array<string, mixed>  $context
     * @return \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult
     */
    public function refuseUnidentifiedResource(string $action, array $context = []): EvaluationResult
    {
        return $this->record($this->currentSubject(), $action, null, $context, EvaluationResult::implicitlyDenied());
    }

    /**
     * Return the most recent evaluation result produced by this process —
     * across every scoped clone and Gate-dispatched path. Request-layer error
     * handlers use this to answer "why was the last check denied?" without
     * re-running the evaluation.
     *
     * Returns null when the process has not yet produced a decision or when the
     * store was explicitly cleared between requests in a long-running worker.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult|null
     */
    public function lastDecision(): ?EvaluationResult
    {
        return $this->lastDecisionStore->get();
    }

    /**
     * Evaluate the supplied action and return the human-readable explanation
     * produced by the resulting trace. Convenience shortcut over
     * `evaluate(...)->explain()` for error-handler output and the future
     * `authorization:why-can` Artisan command.
     *
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return string
     */
    public function explain(string $action, ?string $resource = null, array $context = []): string
    {
        return $this->evaluate($action, $resource, $context)->explain();
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
     * Walks every case of every configured `PermissionEnum` and evaluates each
     * through the full 4-step evaluator (explicit deny, explicit allow, RBAC,
     * implicit deny). The result is an associative array keyed by permission
     * string with boolean values indicating whether the subject is allowed.
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
     * Evaluate the action against the supplied subject.
     *
     * A subject that is inactive, or whose identity is, is denied everything
     * before any policy is read. RBAC is consulted only when no policy decided
     * the check: an explicit allow or deny, or an invalid policy, stands. A
     * policy document that cannot be read denies the check as an invalid
     * policy. The subject's identity, when it is another model, contributes its
     * policies and its grants (see `SubjectGrants`).
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult
     */
    private function evaluateFor(?Subject $subject, string $action, ?string $resource, array $context): EvaluationResult
    {
        if ($subject === null) {
            return EvaluationResult::implicitlyDenied();
        }

        if (SubjectGrants::isInactive($subject)) {
            return EvaluationResult::subjectInactive();
        }

        $result = $this->evaluatePolicies($subject, $action, $resource, $context);

        if ($result->reason === DecisionReason::IMPLICIT_DENY && SubjectGrants::holdsPermission($subject, $action)) {
            return EvaluationResult::rbacAllowed($result->trace);
        }

        return $result;
    }

    /**
     * Evaluate the subject's policies, and its identity's. A policy document
     * that cannot be read denies the check as an invalid policy.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult
     */
    private function evaluatePolicies(Subject $subject, string $action, ?string $resource, array $context): EvaluationResult
    {
        try {
            $policies = $this->gatherPolicies($subject);
        } catch (InvalidPolicyDocumentException) {
            return EvaluationResult::invalidPolicy();
        }

        return $this->evaluator->evaluate($policies, $action, $resource, $context, $subject->subject);
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
     * Record the result as the last decision and dispatch its decision event.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult  $result
     * @return \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult
     */
    private function record(?Subject $subject, string $action, ?string $resource, array $context, EvaluationResult $result): EvaluationResult
    {
        $this->lastDecisionStore->put($result);
        $this->dispatch(new DecisionEvaluated($subject?->subject, $action, $resource, $context, $result));

        return $result;
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
