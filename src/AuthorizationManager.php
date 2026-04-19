<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization;

use Illuminate\Contracts\Events\Dispatcher;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\EvaluationResult;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Traits\HasContainerInstance;

/**
 * Authorization manager — the facade-facing entry point.
 *
 * Coordinates principal resolution, policy gathering, evaluation, and
 * RBAC fallback into a single API. The manager is deliberately small
 * and delegates the actual statement walking to the policy evaluator;
 * all four evaluation branches ultimately return an evaluation
 * result, with the reason code and trace recorded for audit
 * consumers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class AuthorizationManager
{
    use HasContainerInstance;

    /** @var object|null Explicit principal supplied via `for()`; ignored unless the override flag is true. */
    private ?object $principalOverride = null;

    /** @var bool Whether `for()` has produced the current scope; false defers to the bound resolver. */
    private bool $principalOverridden = false;

    /** @var array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>|null  Per-call policy override supplied via `withPolicies()`. */
    private ?array $policyOverride = null;

    /**
     * Create a new manager instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator  $evaluator
     * @param  \SineMacula\Laravel\Authorization\Contracts\PrincipalResolver  $principalResolver
     * @param  \SineMacula\Laravel\Authorization\Contracts\PolicyResolver  $policyResolver
     * @param  \SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore  $lastDecisionStore
     * @param  \Illuminate\Contracts\Events\Dispatcher|null  $events
     */
    public function __construct(

        /** Policy evaluator used to walk statements for every check. */
        private readonly PolicyEvaluator $evaluator,

        /** Bridge to the host application's concept of the current principal. */
        private readonly PrincipalResolver $principalResolver,

        /** Gathers the policy set applicable to a principal per check. */
        private readonly PolicyResolver $policyResolver,

        /** Shared single-slot store holding the last evaluation result. */
        private readonly LastDecisionStore $lastDecisionStore,

        /** Event dispatcher used to emit decision events; null disables. */
        private readonly ?Dispatcher $events = null,

    ) {}

    /**
     * Determine whether the current principal is allowed to perform
     * the supplied action.
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
     * Authorize the current principal for the supplied action, raising
     * an authorization exception when denied.
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
        $principal = $this->currentPrincipal();
        $result    = $this->evaluateFor($principal, $action, $resource, $context);

        $this->lastDecisionStore->put($result);
        $this->dispatch(new DecisionEvaluated($principal, $action, $resource, $context, $result));

        if (!$result->allowed) {
            $this->dispatch(new AuthorizationFailed($principal, $action, $resource, $context, $result));

            throw new AuthorizationException($action, $resource, $result);
        }
    }

    /**
     * Evaluate the supplied action for the current principal and
     * return the full evaluation result.
     *
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult
     */
    public function evaluate(string $action, ?string $resource = null, array $context = []): EvaluationResult
    {
        $principal = $this->currentPrincipal();
        $result    = $this->evaluateFor($principal, $action, $resource, $context);

        $this->lastDecisionStore->put($result);
        $this->dispatch(new DecisionEvaluated($principal, $action, $resource, $context, $result));

        return $result;
    }

    /**
     * Return the most recent evaluation result produced by this
     * process — across every scoped clone and Gate-dispatched path.
     * Request-layer error handlers use this to answer "why was the
     * last check denied?" without re-running the evaluation.
     *
     * Returns null when the process has not yet produced a
     * decision or when the store was explicitly cleared between
     * requests in a long-running worker.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult|null
     */
    public function lastDecision(): ?EvaluationResult
    {
        return $this->lastDecisionStore->get();
    }

    /**
     * Evaluate the supplied action and return the human-readable
     * explanation produced by the resulting trace. Convenience
     * shortcut over `evaluate(...)->explain()` for error-handler
     * output and the future `authorization:why-can` Artisan
     * command.
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
     * Clear the recorded last decision. Long-running workers call
     * this between requests so a stale decision does not leak
     * across the request boundary.
     *
     * @return void
     */
    public function forgetLastDecision(): void
    {
        $this->lastDecisionStore->forget();
    }

    /**
     * Return a map of every registered permission to its effective
     * decision for the current principal.
     *
     * Walks every case of every configured `PermissionEnum` and
     * evaluates each through the full 4-step evaluator (explicit
     * deny, explicit allow, RBAC, implicit deny). The result is an
     * associative array keyed by permission string with boolean
     * values indicating whether the principal is allowed.
     *
     * Performance note: this method performs N evaluations where
     * N is the total number of registered enum cases. Callers should
     * cache the result when rendering permission-picker UIs or
     * capability checklists rather than calling this on every
     * request.
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
            if (!\is_string($enumClass) || !\is_subclass_of($enumClass, PermissionEnum::class)) {
                continue;
            }

            /** @var class-string<\SineMacula\Laravel\Authorization\Contracts\PermissionEnum> $className */
            $className = $enumClass;

            foreach ($className::cases() as $case) {
                $action = $case->value;
                \assert(\is_string($action));
                $permissions[$action] = $this->can($action, null, $context);
            }
        }

        return $permissions;
    }

    /**
     * Return a scoped manager bound to the supplied principal.
     *
     * @param  object  $principal
     * @return static
     */
    public function for(object $principal): static
    {
        $scoped                      = clone $this;
        $scoped->principalOverride   = $principal;
        $scoped->principalOverridden = true;

        return $scoped;
    }

    /**
     * Return a scoped manager that evaluates only the supplied
     * policies, bypassing the principal's own attached policies and
     * any configured policy store.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return static
     */
    public function withPolicies(array $policies): static
    {
        $scoped                 = clone $this;
        $scoped->policyOverride = \array_values($policies);

        return $scoped;
    }

    /**
     * Resolve the principal in scope for this invocation.
     *
     * Honours a `for()` override when active; otherwise defers to the
     * bound `PrincipalResolver`. Public so every surface that needs the
     * current principal — middleware, Blade helpers, custom Gates — can
     * delegate here instead of re-implementing the override + resolver
     * trio.
     *
     * @return object|null
     */
    public function currentPrincipal(): ?object
    {
        if ($this->principalOverridden) {
            return $this->principalOverride;
        }

        return $this->principalResolver->resolve();
    }

    /**
     * Evaluate the action against the supplied principal.
     *
     * @param  object|null  $principal
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult
     */
    private function evaluateFor(
        ?object $principal,
        string $action,
        ?string $resource,
        array $context,
    ): EvaluationResult {
        if ($principal === null) {
            return EvaluationResult::implicitlyDenied();
        }

        $policies = $this->gatherPolicies($principal);
        $result   = $this->evaluator->evaluate($policies, $action, $resource, $context, $principal);
        $decisive = $result->reason === DecisionReason::EXPLICIT_DENY
            || $result->reason      === DecisionReason::EXPLICIT_ALLOW;

        if (!$decisive && $principal instanceof AuthorizableIdentity && $principal->hasPermission($action)) {
            return EvaluationResult::rbacAllowed($result->trace);
        }

        return $result;
    }

    /**
     * Gather the policies applicable to the supplied principal.
     *
     * When a per-call override is in effect, it is returned
     * verbatim. Otherwise the manager delegates to the bound
     * `PolicyResolver` — consumers swap the resolver to introduce
     * caching, tenant scoping, or other gathering strategies
     * without touching the manager.
     *
     * @param  object  $principal
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    private function gatherPolicies(object $principal): array
    {
        if ($this->policyOverride !== null) {
            return $this->policyOverride;
        }

        return $this->policyResolver->policiesFor($principal);
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
