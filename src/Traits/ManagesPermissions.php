<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Traits;

use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Events\Role\PermissionGranted as RolePermissionGranted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionRevoked as RolePermissionRevoked;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Pivots\RolePermission;

/**
 * Role-side permission management API.
 *
 * Owns the `Role → Permission` relation and every give / revoke / has
 * / sync / get helper consumers call against a Role. Extracted from
 * `Role` so the model keeps to schema, relations, and lifecycle.
 *
 * Fires `RolePermissionGranted` on every attachment and
 * `RolePermissionRevoked` on every detachment so the cache
 * invalidation listener keeps the resolution cache coherent and
 * audit consumers receive the same per-row signal regardless of the
 * entry point (`givePermission`, `revokePermission`,
 * `syncPermissions`, or a raw `$role->permissions()->attach()`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \SineMacula\Laravel\Authorization\Models\Role
 */
trait ManagesPermissions // @phpstan-ignore trait.unused
{
    /**
     * Permissions attached to this role.
     *
     * The relation is bound to the `RolePermission` pivot so every
     * attachment path — the typed Role API, a direct
     * `$role->permissions()->attach(...)`, or a raw
     * `sync(...)` — runs through the pivot's `saving` hook and the
     * guard-parity invariant it enforces.
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany<\SineMacula\Laravel\Authorization\Models\Permission, $this,
     *     \SineMacula\Laravel\Authorization\Models\Pivots\RolePermission, 'pivot'>
     *
     * @formatter:on
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     */
    public function permissions(): BelongsToMany
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $permissionModel */
        $permissionModel = config('authorization.models.permission', Permission::class);

        /** @var string $pivot */
        $pivot = config('authorization.tables.role_permissions', 'role_permissions');

        return $this->belongsToMany(
            related        : $permissionModel,
            table          : $pivot,
            foreignPivotKey: 'role_id',
            relatedPivotKey: 'permission_id',
        )->using(RolePermission::class);
    }

    /**
     * Attach the given permission to this role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return static
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    public function givePermission(Permission|string $permission): static
    {
        $model = $this->resolvePermission($permission);

        $this->permissions()->syncWithoutDetaching([$model->getKey()]);

        if (isset($this->relations['permissions'])) {
            unset($this->relations['permissions']);
        }

        Event::dispatch(new RolePermissionGranted($this, $model));

        return $this;
    }

    /**
     * Spatie alias for the canonical `givePermission()` helper.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return static
     */
    public function givePermissionTo(Permission|string $permission): static
    {
        return $this->givePermission($permission);
    }

    /**
     * Detach the given permission from this role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return static
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    public function revokePermission(Permission|string $permission): static
    {
        $model = $this->resolvePermission($permission);

        $this->permissions()->detach($model->getKey());

        if (isset($this->relations['permissions'])) {
            unset($this->relations['permissions']);
        }

        Event::dispatch(new RolePermissionRevoked($this, $model));

        return $this;
    }

    /**
     * Spatie alias for the canonical `revokePermission()` helper.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return static
     */
    public function revokePermissionTo(Permission|string $permission): static
    {
        return $this->revokePermission($permission);
    }

    /**
     * Replace this role's permission set with the supplied list.
     *
     * Each net attachment fires `RolePermissionGranted` and each net
     * detachment fires `RolePermissionRevoked`, so audit consumers
     * receive the same per-row signal they would for
     * `givePermission()` / `revokePermission()` calls and the cache
     * invalidation listener wired to those events keeps the
     * resolution cache coherent.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Permission|string>  $permissions
     * @return static
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    public function syncPermissions(array $permissions): static
    {
        $resolved = [];

        foreach ($permissions as $permission) {
            $model                = $this->resolvePermission($permission);
            $resolved[$model->id] = $model;
        }

        $ids    = \array_keys($resolved);
        $result = $this->permissions()->sync($ids);

        if (isset($this->relations['permissions'])) {
            unset($this->relations['permissions']);
        }

        foreach ($result['attached'] as $id) {
            Event::dispatch(new RolePermissionGranted($this, $resolved[(string) $id] ?? $this->resolvePermissionById((string) $id)));
        }

        foreach ($result['detached'] as $id) {
            Event::dispatch(new RolePermissionRevoked($this, $this->resolvePermissionById((string) $id)));
        }

        return $this;
    }

    /**
     * Determine whether this role carries the given permission.
     *
     * A held permission name is treated as an `fnmatch` pattern
     * against the asked name — so a role that holds `posts:*`
     * satisfies `hasPermission('posts:create')`, and a role that
     * holds `*:*` satisfies every check. The reverse direction does
     * not match: holding `posts:create` does not satisfy an asked
     * `posts:*`. Backslashes are compared literally via
     * `FNM_NOESCAPE`.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return bool
     */
    public function hasPermission(Permission|string $permission): bool
    {
        $asked = $permission instanceof Permission ? $permission->name : $permission;

        foreach ($this->getPermissions() as $held) {
            if (\fnmatch($held, $asked, \FNM_NOESCAPE)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Spatie alias for the canonical `hasPermission()` helper.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return bool
     */
    public function hasPermissionTo(Permission|string $permission): bool
    {
        return $this->hasPermission($permission);
    }

    /**
     * Return the names of every permission this role holds.
     *
     * When `authorization.hierarchy.enabled` is true (the default),
     * this includes the deduplicated union of the role's own direct
     * permissions and all permissions inherited from ancestor roles.
     * When hierarchy is disabled, only directly attached permissions
     * are returned.
     *
     * @return array<int, string>
     */
    public function getPermissions(): array
    {
        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission> $permissions */
        $permissions = $this->permissions;

        $names = $permissions->map(static fn (Permission $permission): string => $permission->name)->all();

        /** @var bool $hierarchyEnabled */
        $hierarchyEnabled = config('authorization.hierarchy.enabled', true);

        if ($hierarchyEnabled && $this->parent_id !== null) {
            foreach ($this->ancestors() as $ancestor) {
                /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission> $ancestorPermissions */
                $ancestorPermissions = $ancestor->permissions;

                foreach ($ancestorPermissions as $ancestorPermission) {
                    $names[] = $ancestorPermission->name;
                }
            }
        }

        return \array_values(\array_unique($names));
    }

    /**
     * Spatie alias for the canonical `getPermissions()` helper.
     *
     * @return array<int, string>
     */
    public function getPermissionNames(): array
    {
        return $this->getPermissions();
    }

    /**
     * Resolve a permission identifier to a model instance.
     *
     * Role rows carry their own `guard`; use it as the lookup scope
     * so a web-scoped role resolves permissions against the web
     * guard and an api-scoped role against the api guard. Falls back
     * to the package default when the role itself is guard-agnostic
     * (null `guard`). Delegates the query to
     * `Permission::resolveByName()` so both sides share one
     * implementation.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    protected function resolvePermission(Permission|string $permission): Permission
    {
        if ($permission instanceof Permission) {
            return $permission;
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $class */
        $class = config('authorization.models.permission', Permission::class);

        return $class::resolveByName($permission, $this->guard);
    }

    /**
     * Resolve a permission model by primary key, used by
     * `syncPermissions()` when the sync delta surfaces an ID that
     * was not part of the caller's input set (the detachment list).
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    private function resolvePermissionById(string $id): Permission
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $class */
        $class = config('authorization.models.permission', Permission::class);

        /** @var \SineMacula\Laravel\Authorization\Models\Permission|null $model */
        $model = $class::query()->whereKey($id)->first();

        if ($model === null) {
            throw new UnknownPermissionException($id);
        }

        return $model;
    }
}
