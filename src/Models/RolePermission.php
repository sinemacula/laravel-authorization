<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

use Illuminate\Database\Eloquent\Relations\Pivot;
use SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException;

/**
 * Custom pivot model for the `role_permissions` table.
 *
 * Owning the pivot lets the guard-parity invariant live on the
 * relationship layer rather than on either primary entity — a
 * direct `$role->permissions()->attach(...)` or `sync(...)` goes
 * through this model's `saving` hook because the parent relation
 * is wired with `using(RolePermission::class)`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class RolePermission extends Pivot
{
    /**
     * Pivot tables do not auto-increment (composite PK).
     *
     * @var bool
     */
    public $incrementing = false;

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
     * Reject a save when the role's guard and the permission's
     * guard are concrete and different.
     *
     * Guard-agnostic rows (null `guard_name`) are compatible with
     * every guard and pass the check unconditionally.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException
     */
    private function ensureGuardParity(): void
    {
        /** @var string|null $roleId */
        $roleId = $this->getAttribute('role_id');
        /** @var string|null $permissionId */
        $permissionId = $this->getAttribute('permission_id');

        if ($roleId === null || $permissionId === null) {
            return;
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $roleClass */
        $roleClass = config('authorization.models.role', Role::class);
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $permissionClass */
        $permissionClass = config('authorization.models.permission', Permission::class);

        /** @var \SineMacula\Laravel\Authorization\Models\Role|null $role */
        $role = $roleClass::query()->find($roleId);
        /** @var \SineMacula\Laravel\Authorization\Models\Permission|null $permission */
        $permission = $permissionClass::query()->find($permissionId);

        if ($role === null || $permission === null) {
            return;
        }

        $roleGuard       = $role->guard_name;
        $permissionGuard = $permission->guard_name;

        if ($roleGuard === null || $permissionGuard === null) {
            return;
        }

        if ($roleGuard !== $permissionGuard) {
            throw new GuardMismatchException(
                roleName: (string) $role->name,
                permissionName: (string) $permission->name,
                roleGuard: $roleGuard,
                permissionGuard: $permissionGuard,
            );
        }
    }
}
