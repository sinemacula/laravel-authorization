<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
use SineMacula\Laravel\Authorization\Models\Role as RoleModel;

/**
 * Principal that satisfies `SupportsRoles` but not `SupportsPermissions` — used
 * to exercise the narrow-contract mismatch branches in
 * `BladeHelpers::hasAllRoles`, `hasPermission`, and `hasAllPermissions`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
final class RolesOnlyPrincipal implements SupportsRoles
{
    /**
     * Assign a role (no-op stub).
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return static
     */
    public function assignRole(RoleModel|string $role): static
    {
        return $this;
    }

    /**
     * Revoke a role (no-op stub).
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return static
     */
    public function revokeRole(RoleModel|string $role): static
    {
        return $this;
    }

    /**
     * Sync roles (no-op stub).
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Role|string>  $roles
     * @return static
     */
    public function syncRoles(array $roles): static
    {
        return $this;
    }

    /**
     * Report whether the principal has the supplied role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return bool
     */
    public function hasRole(RoleModel|string $role): bool
    {
        return $role === 'editor';
    }

    /**
     * List the roles granted to the principal.
     *
     * @return array<int, string>
     */
    public function getRoles(): array
    {
        return ['editor'];
    }
}
