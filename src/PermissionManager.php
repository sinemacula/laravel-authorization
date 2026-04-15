<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Permissions;

use SineMacula\Laravel\Iam\Auth\Contracts\Principal;
use SineMacula\Laravel\Iam\Auth\Facades\Auth;
use SineMacula\Laravel\Iam\Permissions\Contracts\Authorizable;
use SineMacula\Laravel\Iam\Permissions\Contracts\PolicyStore;
use SineMacula\Laravel\Iam\Permissions\Evaluation\EvaluationResult;
use SineMacula\Laravel\Iam\Permissions\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Iam\Permissions\Exceptions\AuthorizationException;

/**
 * Permission manager.
 *
 * The main entry point for the permissions sub-package. Combines
 * simple RBAC checks with IAM-style policy evaluation. An explicit
 * policy DENY always overrides an RBAC allow.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
class PermissionManager
{
    /**
     * Create a new permission manager instance.
     *
     * @param  \SineMacula\Laravel\Iam\Permissions\Evaluation\PolicyEvaluator  $evaluator
     * @param  \SineMacula\Laravel\Iam\Permissions\Contracts\PolicyStore|null  $policyStore
     */
    public function __construct(
        private readonly PolicyEvaluator $evaluator,
        private readonly ?PolicyStore $policyStore = null,
    ) {}

    /**
     * Determine whether the current principal is allowed to perform
     * the given action.
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
     * Authorize the current principal for the given action, throwing
     * an exception if denied.
     *
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Permissions\Exceptions\AuthorizationException
     */
    public function authorize(string $action, ?string $resource = null, array $context = []): void
    {
        $result = $this->evaluate($action, $resource, $context);

        if (!$result->allowed) {
            throw new AuthorizationException($action, $resource, $result);
        }
    }

    /**
     * Evaluate the current principal's access to the given action
     * and return the full evaluation result.
     *
     * The evaluation order is:
     * 1. If a PolicyStore is configured, evaluate IAM policies first
     * 2. If any policy explicitly denies, return DENY immediately
     * 3. If any policy explicitly allows, return ALLOW
     * 4. If the principal implements Authorizable, check RBAC
     * 5. Otherwise, return implicit DENY
     *
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return \SineMacula\Laravel\Iam\Permissions\Evaluation\EvaluationResult
     */
    public function evaluate(string $action, ?string $resource = null, array $context = []): EvaluationResult
    {
        $principal = $this->resolvePrincipal();

        if ($principal === null) {
            return EvaluationResult::implicitlyDenied();
        }

        return $this->resolveResult($principal, $action, $resource, $context);
    }

    /**
     * Resolve the final evaluation result for the given principal.
     *
     * Checks IAM policies first (explicit deny or allow), then falls
     * back to RBAC permissions, and defaults to implicit deny.
     *
     * @param  \SineMacula\Laravel\Iam\Auth\Contracts\Principal  $principal
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return \SineMacula\Laravel\Iam\Permissions\Evaluation\EvaluationResult
     */
    private function resolveResult(Principal $principal, string $action, ?string $resource, array $context): EvaluationResult
    {
        $policyResult = $this->evaluatePolicies($principal, $action, $resource, $context);

        if ($policyResult !== null && $policyResult->reason !== EvaluationResult::REASON_IMPLICIT_DENY) {
            return $policyResult;
        }

        if ($principal instanceof Authorizable && $principal->hasPermission($action)) {
            return EvaluationResult::rbacAllowed();
        }

        return EvaluationResult::implicitlyDenied();
    }

    /**
     * Resolve the current principal from the auth context.
     *
     * @return \SineMacula\Laravel\Iam\Auth\Contracts\Principal|null
     */
    private function resolvePrincipal(): ?Principal
    {
        return Auth::principal();
    }

    /**
     * Evaluate IAM-style policies for the given principal.
     *
     * Returns null when no policy store is configured and the
     * principal does not provide policies directly.
     *
     * @param  \SineMacula\Laravel\Iam\Auth\Contracts\Principal  $principal
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return \SineMacula\Laravel\Iam\Permissions\Evaluation\EvaluationResult|null
     */
    private function evaluatePolicies(Principal $principal, string $action, ?string $resource, array $context): ?EvaluationResult
    {
        $policies = $this->gatherPolicies($principal);

        if ($policies === []) {
            return null;
        }

        return $this->evaluator->evaluate($policies, $action, $resource, $context);
    }

    /**
     * Gather all applicable policies for the given principal.
     *
     * Combines policies from the PolicyStore (if configured) with
     * any policies provided directly by the principal (if it
     * implements Authorizable).
     *
     * @param  \SineMacula\Laravel\Iam\Auth\Contracts\Principal  $principal
     * @return array<int, \SineMacula\Laravel\Iam\Permissions\Evaluation\Policy>
     */
    private function gatherPolicies(Principal $principal): array
    {
        $policies = [];

        if ($this->policyStore !== null) {
            $policies = $this->policyStore->policiesFor($principal->getPrincipalIdentifier());
        }

        if ($principal instanceof Authorizable) {
            $policies = array_merge($policies, $principal->getPolicies());
        }

        return $policies;
    }
}
