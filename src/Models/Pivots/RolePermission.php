<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models\Pivots;

use Illuminate\Database\Eloquent\Relations\Pivot;
use SineMacula\Laravel\Authorization\Enums\OrphanSide;
use SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\OrphanedRolePermissionException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Custom pivot model for the `role_permissions` table.
 *
 * Owning the pivot lets the guard-parity invariant live on the relationship
 * layer rather than on either primary entity — a direct
 * `$role->permissions()->attach(...)` or `sync(...)` goes through this model's
 * `saving` hook because the parent relation is wired with
 * `using(RolePermission::class)`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class RolePermission extends Pivot
{
    /**
     * Boot the pivot and register the guard-parity hook.
     *
     * @return void
     */
    protected static function booted(): void
    {
        static::saving(static function (self $pivot): void {
            $pivot->ensureGuardParity();
        });
    }

    /**
     * Reject a save when the role's and permission's guards are concrete and
     * different. Guard-agnostic (`null`) rows pass. Parent models are resolved
     * from the in-memory `pivotParent` / loaded relations where possible; a
     * missing parent raises `OrphanedRolePermissionException`.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OrphanedRolePermissionException
     */
    private function ensureGuardParity(): void
    {
        $roleColumn       = $this->resolveRoleColumn();
        $permissionColumn = $this->resolvePermissionColumn();

        /** @var string|null $roleId */
        $roleId = $this->getAttribute($roleColumn);
        /** @var string|null $permissionId */
        $permissionId = $this->getAttribute($permissionColumn);

        if ($roleId === null || $permissionId === null) {
            return;
        }

        $role       = $this->resolveRoleParent($roleId);
        $permission = $this->resolvePermissionParent($permissionId);

        $roleGuard       = $role->guard;
        $permissionGuard = $permission->guard;

        if ($roleGuard === null || $permissionGuard === null) {
            return;
        }

        if ($roleGuard !== $permissionGuard) {
            throw new GuardMismatchException(roleName: $role->name, permissionName: $permission->name, roleGuard: $roleGuard, permissionGuard: $permissionGuard);
        }
    }

    /**
     * Resolve the role-side parent model, preferring an in-memory instance over
     * a fresh database lookup.
     *
     * @param  string  $roleId
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OrphanedRolePermissionException
     */
    private function resolveRoleParent(string $roleId): Role
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $roleClass */
        $roleClass = config('authorization.models.role', Role::class);

        $parent = $this->pivotParent;

        if ($parent instanceof $roleClass && $parent->id === $roleId) {
            return $parent;
        }

        if ($this->relationLoaded('role')) {
            /** @var \SineMacula\Laravel\Authorization\Models\Role|null $loaded */
            $loaded = $this->getRelation('role');

            if ($loaded instanceof $roleClass && $loaded->id === $roleId) {
                return $loaded;
            }
        }

        /** @var \SineMacula\Laravel\Authorization\Models\Role|null $role */
        $role = $roleClass::query()->find($roleId);

        if ($role === null) {
            throw new OrphanedRolePermissionException(side: OrphanSide::ROLE, parentId: $roleId);
        }

        return $role;
    }

    /**
     * Resolve the permission-side parent model, preferring an in-memory
     * instance over a fresh database lookup.
     *
     * @param  string  $permissionId
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OrphanedRolePermissionException
     */
    private function resolvePermissionParent(string $permissionId): Permission
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $permissionClass */
        $permissionClass = config('authorization.models.permission', Permission::class);

        $parent = $this->pivotParent;

        // @codeCoverageIgnoreStart
        // Defensive symmetry with resolveRoleParent(): pivotParent
        // is only set by BelongsToMany traversal, and only Role's
        // permissions() relation uses this pivot via `using()`.
        // Reaching this branch requires a consumer-side
        // `Permission::roles()` relation that opts into
        // `->using(RolePermission::class)`, kept for forward
        // symmetry when that override ships.
        if ($parent instanceof $permissionClass && $parent->id === $permissionId) {
            return $parent;
        }
        // @codeCoverageIgnoreEnd

        if ($this->relationLoaded('permission')) {
            /** @var \SineMacula\Laravel\Authorization\Models\Permission|null $loaded */
            $loaded = $this->getRelation('permission');

            if ($loaded instanceof $permissionClass && $loaded->id === $permissionId) {
                return $loaded;
            }
        }

        /** @var \SineMacula\Laravel\Authorization\Models\Permission|null $permission */
        $permission = $permissionClass::query()->find($permissionId);

        if ($permission === null) {
            throw new OrphanedRolePermissionException(side: OrphanSide::PERMISSION, parentId: $permissionId);
        }

        return $permission;
    }

    /**
     * Resolve the pivot's role-side column name.
     *
     * Laravel populates the pivot's foreign / related keys via `setPivotKeys()`
     * when the row is instantiated through a `BelongsToMany` relation — that
     * path is preferred so a consumer who renames the FK on the relation
     * definition still gets the invariant enforced. Direct instantiation (no
     * parent relation) falls back to config, which defaults to `role_id`.
     *
     * @return string
     */
    private function resolveRoleColumn(): string
    {
        $key = $this->getForeignKey();

        // The pivot's `$foreignKey` property is untyped on the
        // upstream AsPivot trait and defaults to null when a pivot
        // is instantiated outside a relation — PHPStan trusts the
        // docblocked string return; runtime does not. Guard it.
        // @phpstan-ignore function.alreadyNarrowedType
        if (is_string($key) && $key !== '') {
            return $key;
        }

        $column = config('authorization.pivots.role_permissions.role_column', 'role_id');

        assert(is_string($column));

        return $column;
    }

    /**
     * Resolve the pivot's permission-side column name.
     *
     * Prefers the relation-supplied `relatedPivotKey` so a renamed FK on the
     * relation definition still enforces the invariant. Falls back to config
     * (default `permission_id`) on direct instantiation paths.
     *
     * @return string
     */
    private function resolvePermissionColumn(): string
    {
        $key = $this->getRelatedKey();

        // See `resolveRoleColumn()` — same upstream-trait null
        // hazard on direct instantiation paths.
        // @phpstan-ignore function.alreadyNarrowedType
        if (is_string($key) && $key !== '') {
            return $key;
        }

        $column = config('authorization.pivots.role_permissions.permission_column', 'permission_id');

        assert(is_string($column));

        return $column;
    }
}
