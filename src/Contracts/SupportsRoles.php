<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use SineMacula\Laravel\Authorization\Models\Role as RoleModel;

/**
 * Narrow contract for identities that carry roles.
 *
 * Split from the composite `AuthorizableIdentity` so a pure-RBAC
 * consumer that only uses role assignment can typehint on the
 * minimum surface they actually implement. The composite
 * contract extends this one so existing implementers stay
 * satisfied.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SupportsRoles
{
    /**
     * Assign the given role to this identity.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return static
     */
    public function assignRole(RoleModel|string $role): static;

    /**
     * Revoke the given role from this identity.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return static
     */
    public function revokeRole(RoleModel|string $role): static;

    /**
     * Replace this identity's roles with the supplied set.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Role|string>  $roles
     * @return static
     */
    public function syncRoles(array $roles): static;

    /**
     * Determine whether this identity has the given role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return bool
     */
    public function hasRole(RoleModel|string $role): bool;

    /**
     * Return the names of every role assigned to this identity.
     *
     * @return array<int, string>
     */
    public function getRoles(): array;
}
