<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization;

use Illuminate\Contracts\Events\Dispatcher;
use SineMacula\Laravel\Authorization\Contracts\Authorizable;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Evaluation\EvaluationResult;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;

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
    /**
     * Explicit principal supplied via `for()`. Ignored unless the
     * override flag is true.
     *
     * @var object|null
     */
    private ?object $principalOverride = null;

    /**
     * Whether `for()` has produced the current scope. When false, the
     * manager defers principal resolution to the bound resolver.
     *
     * @var bool
     */
    private bool $principalOverridden = false;

    /**
     * Per-call policy override supplied via `withPolicies()`.
     *
     * @var array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>|null
     */
    private ?array $policyOverride = null;

    /**
     * Create a new manager instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator  $evaluator
     * @param  \SineMacula\Laravel\Authorization\Contracts\PrincipalResolver  $resolver
     * @param  \SineMacula\Laravel\Authorization\Contracts\PolicyStore|null  $store
     * @param  \Illuminate\Contracts\Events\Dispatcher|null  $events
     */
    public function __construct(

        /** Policy evaluator used to walk statements for every check. */
        private readonly PolicyEvaluator $evaluator,

        /** Bridge to the host application's concept of the current principal. */
        private readonly PrincipalResolver $resolver,

        /** Optional external policy source unioned with a principal's attached policies. */
        private readonly ?PolicyStore $store = null,

        /** Event dispatcher used to emit decision events, or null when unavailable. */
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

        $this->dispatch(new DecisionEvaluated($principal, $action, $resource, $context, $result));

        return $result;
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
     * @return object|null
     */
    private function currentPrincipal(): ?object
    {
        if ($this->principalOverridden) {
            return $this->principalOverride;
        }

        return $this->resolver->resolve();
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
    private function evaluateFor(?object $principal, string $action, ?string $resource, array $context): EvaluationResult
    {
        if ($principal === null) {
            return EvaluationResult::implicitlyDenied();
        }

        $policies = $this->gatherPolicies($principal);
        $result   = $this->evaluator->evaluate($policies, $action, $resource, $context);
        $decisive = $result->reason === EvaluationResult::REASON_EXPLICIT_DENY
            || $result->reason      === EvaluationResult::REASON_EXPLICIT_ALLOW;

        if (!$decisive && $principal instanceof Authorizable && $principal->hasPermission($action)) {
            return EvaluationResult::rbacAllowed($result->trace);
        }

        return $result;
    }

    /**
     * Gather the policies applicable to the supplied principal.
     *
     * When a per-call override is in effect, it is returned verbatim.
     * Otherwise the manager unions policies from an optional policy
     * store binding with the principal's own attached policies.
     *
     * @param  object  $principal
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    private function gatherPolicies(object $principal): array
    {
        if ($this->policyOverride !== null) {
            return $this->policyOverride;
        }

        $policies = [];

        if ($this->store !== null) {
            $policies = $this->store->policiesFor($principal);
        }

        if ($principal instanceof Authorizable) {
            $policies = \array_merge($policies, $principal->getPolicies());
        }

        return \array_values($policies);
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
