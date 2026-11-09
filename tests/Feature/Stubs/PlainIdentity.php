<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * An authorizable identity that is no Eloquent model but claims to exist as a
 * saved model does, holding nothing and changing nothing it is given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PlainIdentity implements AuthorizableIdentity
{
    /** @var bool Whether it claims to be saved, as a saved model does. */
    public bool $exists = true;

    /**
     * Give it the permission, which it ignores.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return static
     */
    #[\Override]
    public function givePermission(Permission|string $permission): static
    {
        return $this;
    }

    /**
     * Revoke the permission, which it ignores.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return static
     */
    #[\Override]
    public function revokePermission(Permission|string $permission): static
    {
        return $this;
    }

    /**
     * Sync the permissions, which it ignores.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Permission|string>  $permissions
     * @return static
     */
    #[\Override]
    public function syncPermissions(array $permissions): static
    {
        return $this;
    }

    /**
     * Determine whether it holds the permission, which it never does.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return bool
     */
    #[\Override]
    public function hasPermission(Permission|string $permission): bool
    {
        return false;
    }

    /**
     * Return its permissions, of which it has none.
     *
     * @return array<int, string>
     */
    #[\Override]
    public function getPermissions(): array
    {
        return [];
    }

    /**
     * Attach the policy, which it ignores.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return static
     */
    #[\Override]
    public function attachPolicy(Policy $policy): static
    {
        return $this;
    }

    /**
     * Detach the policy, which it ignores.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return static
     */
    #[\Override]
    public function detachPolicy(Policy $policy): static
    {
        return $this;
    }

    /**
     * Sync the policies, which it ignores.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Policy>  $policies
     * @return static
     */
    #[\Override]
    public function syncPolicies(array $policies): static
    {
        return $this;
    }

    /**
     * Return its policies, of which it has none.
     *
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    #[\Override]
    public function getPolicies(): array
    {
        return [];
    }

    /**
     * Assign the role, which it ignores.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return static
     */
    #[\Override]
    public function assignRole(Role|string $role): static
    {
        return $this;
    }

    /**
     * Revoke the role, which it ignores.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return static
     */
    #[\Override]
    public function revokeRole(Role|string $role): static
    {
        return $this;
    }

    /**
     * Sync the roles, which it ignores.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Role|string>  $roles
     * @return static
     */
    #[\Override]
    public function syncRoles(array $roles): static
    {
        return $this;
    }

    /**
     * Determine whether it holds the role, which it never does.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  string|null  $guard
     * @return bool
     */
    #[\Override]
    public function hasRole(Role|string $role, ?string $guard = null): bool
    {
        return false;
    }

    /**
     * Return its roles, of which it has none.
     *
     * @return array<int, string>
     */
    #[\Override]
    public function getRoles(): array
    {
        return [];
    }

    /**
     * Determine whether it is active, which it always is.
     *
     * @return bool
     */
    #[\Override]
    public function isAuthorizationActive(): bool
    {
        return true;
    }
}
