<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use SineMacula\Laravel\Authorization\Models\Policy as PolicyModel;

/**
 * Narrow contract for grantees, identities or roles, that carry attached
 * policies.
 *
 * Split from the composite `AuthorizableIdentity` so a consumer who only needs
 * policy attachment — no direct RBAC grants — can typehint on the minimum
 * surface they actually implement. The parameters take the shipped `Policy`,
 * which the class `authorization.models.policy` configures extends; any other
 * model is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SupportsPolicies
{
    /**
     * Attach the given policy to this grantee.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return static
     */
    public function attachPolicy(PolicyModel $policy): static;

    /**
     * Detach the given policy from this grantee.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return static
     */
    public function detachPolicy(PolicyModel $policy): static;

    /**
     * Replace the grantee's attached policies with the supplied set.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Policy>  $policies
     * @return static
     */
    public function syncPolicies(array $policies): static;

    /**
     * Return the evaluation-ready policy value objects attached to this
     * grantee.
     *
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public function getPolicies(): array;
}
