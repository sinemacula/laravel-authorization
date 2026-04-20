<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use SineMacula\Laravel\Authorization\Models\Permission as PermissionModel;

/**
 * Narrow contract for identities that carry direct permission grants and
 * resolve permissions (direct + role-inherited).
 *
 * Split from the composite `AuthorizableIdentity` so a pure-RBAC consumer that
 * only wires permissions can typehint on the minimum surface they actually
 * implement.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SupportsPermissions
{
    /**
     * Grant the given permission directly to this identity.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return static
     */
    public function givePermission(PermissionModel|string $permission): static;

    /**
     * Revoke the given direct permission from this identity.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return static
     */
    public function revokePermission(PermissionModel|string $permission): static;

    /**
     * Replace this identity's direct permissions with the supplied set.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Permission|string>  $permissions
     * @return static
     */
    public function syncPermissions(array $permissions): static;

    /**
     * Determine whether this identity has the given permission either directly
     * or through any assigned role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return bool
     */
    public function hasPermission(PermissionModel|string $permission): bool;

    /**
     * Return the names of every permission the identity holds, either directly
     * or through its assigned roles.
     *
     * @return array<int, string>
     */
    public function getPermissions(): array;
}
