<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Models\Policy as PolicyModel;

/**
 * Narrow contract for identities that carry attached policies.
 *
 * Split from the composite `AuthorizableIdentity` so a consumer
 * who only needs policy attachment — no direct RBAC grants — can
 * typehint on the minimum surface they actually implement. The
 * parameters widen to `Policy|Model` to match the shipped trait,
 * letting consumers pass their own policy subclass or a
 * duck-typed model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SupportsPolicies
{
    /**
     * Attach the given policy to this identity.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return static
     */
    public function attachPolicy(Model|PolicyModel $policy): static;

    /**
     * Detach the given policy from this identity.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return static
     */
    public function detachPolicy(Model|PolicyModel $policy): static;

    /**
     * Replace the identity's attached policies with the supplied set.
     *
     * @param  array<int, \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Models\Policy>  $policies
     * @return static
     */
    public function syncPolicies(array $policies): static;

    /**
     * Return the evaluation-ready policy value objects attached
     * to this identity.
     *
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public function getPolicies(): array;
}
