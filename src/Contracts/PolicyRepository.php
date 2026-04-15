<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use SineMacula\Laravel\Authorization\Evaluation\Policy;

/**
 * Internal policy-gathering contract.
 *
 * `PolicyStore` models *external* sources (JWT-embedded policies,
 * config-shipped policies, remote APIs). `PolicyRepository` models
 * the *internal gathering strategy* the authorization manager uses
 * to answer "what policies apply to this principal right now?" —
 * typically the union of an optional `PolicyStore` and the
 * principal's own attached policies.
 *
 * Swapping the repository is the hook for alternate gathering
 * strategies: an aggressive per-request cache, a tenant-scoped
 * pre-loader, a role-hierarchy expander, a test fake. The manager
 * never talks to the Eloquent layer directly — it only ever asks
 * the bound repository.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PolicyRepository
{
    /**
     * Return every policy the authorization manager should consider
     * for the supplied principal.
     *
     * Implementations are free to return an empty list when the
     * principal has no applicable policies. Order is not
     * significant — the evaluator re-orders via its own decision
     * rules (`explicit deny` wins regardless of position).
     *
     * @param  object  $principal
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public function policiesFor(object $principal): array;
}
