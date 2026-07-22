<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Internal policy-gathering contract.
 *
 * Sits alongside `PrincipalResolver` and answers the symmetric question —
 * `PrincipalResolver::resolve()` returns the principal in scope,
 * `PolicyResolver::policiesFor()` returns the policies in scope for that
 * principal.
 *
 * `PolicyStore` models *external* sources (JWT-embedded policies,
 * config-shipped policies, remote APIs). `PolicyResolver` models the *internal
 * gathering strategy* the authorization manager uses to answer "what policies
 * apply to this principal right now?" — typically the union of an optional
 * `PolicyStore` and the principal's own attached policies.
 *
 * Swapping the resolver is the hook for alternate gathering strategies: an
 * aggressive per-request cache, a tenant-scoped pre-loader, a role-hierarchy
 * expander, a test fake. The manager never talks to the Eloquent layer directly
 * — it only ever asks the bound resolver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PolicyResolver
{
    /**
     * Return every policy the authorization manager should consider for the
     * supplied principal.
     *
     * Implementations are free to return an empty list when the principal has
     * no applicable policies. Order is not significant — the evaluator
     * re-orders via its own decision rules (`explicit deny` wins regardless of
     * position).
     *
     * @param  object  $principal
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public function policiesFor(object $principal): array;
}
