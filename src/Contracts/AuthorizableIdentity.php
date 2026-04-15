<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use SineMacula\Laravel\Authorization\Models\Permission as PermissionModel;
use SineMacula\Laravel\Authorization\Models\Policy as PolicyModel;
use SineMacula\Laravel\Authorization\Models\Role as RoleModel;

/**
 * Authorizable identity contract.
 *
 * Implemented by any identity model that participates in the
 * authorization system. Concrete models typically satisfy the
 * contract by composing the package's shipped traits. The explicit
 * `Identity` suffix avoids a name collision with Laravel's built-in
 * `Illuminate\Contracts\Auth\Access\Authorizable` contract.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuthorizableIdentity
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
     * Determine whether this identity has the given permission either
     * directly or through any assigned role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return bool
     */
    public function hasPermission(PermissionModel|string $permission): bool;

    /**
     * Return the names of every permission the identity holds, either
     * directly or through its assigned roles.
     *
     * @return array<int, string>
     */
    public function getPermissions(): array;

    /**
     * Attach the given policy to this identity.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return static
     */
    public function attachPolicy(PolicyModel $policy): static;

    /**
     * Detach the given policy from this identity.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return static
     */
    public function detachPolicy(PolicyModel $policy): static;

    /**
     * Replace the identity's attached policies with the supplied set.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Policy>  $policies
     * @return static
     */
    public function syncPolicies(array $policies): static;

    /**
     * Return the evaluation-ready policy value objects attached to this
     * identity.
     *
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public function getPolicies(): array;
}
