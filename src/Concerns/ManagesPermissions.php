<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use SineMacula\Laravel\Authorization\Database\LiveGrants;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Pivots\RolePermission;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\RoleGraph;

/**
 * Role-side permission management API.
 *
 * Owns the `Role → Permission` relation and every give / revoke / has / sync /
 * get helper consumers call against a Role. Extracted from `Role` so the model
 * keeps to schema, relations, and lifecycle.
 *
 * The write helpers (`givePermission`, `revokePermission`, `syncPermissions`)
 * delegate to the role service, which writes in one transaction and fires
 * `RolePermissionGranted` for each permission really attached and
 * `RolePermissionRevoked` for each really detached, so the cache invalidation
 * listener keeps the resolution cache coherent and audit consumers receive one
 * signal per change. A raw relation write (`$role->permissions()->attach()`,
 * `detach()` or `sync()`) bypasses the service: it fires none of those events
 * and leaves the resolution cache stale, so it is unsupported for any change
 * that must be audited.
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
     * The relation is bound to the `RolePermission` pivot so every attachment
     * path — the role service, a direct `$role->permissions()->attach(...)`, or
     * a raw `sync(...)` — runs through the pivot's `saving` hook and the
     * guard-parity invariant it enforces. Only the role service reports the
     * change. A permission whose grant to the role has expired is left out, and
     * each carries its expiry as `$permission->pivot->expires_at`.
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
        )->using(RolePermission::class)
            ->withPivot('expires_at')
            ->where(static function (Builder $query) use ($pivot): void {
                LiveGrants::only($query, $pivot);
            });
    }

    /**
     * Attach the given permission to this role, through the role service.
     *
     * An optional `$expiresAt` makes the grant temporal: the role stops
     * carrying the permission the moment the clock passes it, without a sweeper
     * run. A permission the role carries with the same expiry is left as it is,
     * and no event fires; one whose grant has expired is re-armed with the new
     * expiry.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  \DateTimeInterface|null  $expiresAt
     * @return static
     *
     * @throws \Throwable
     */
    public function givePermission(Permission|string $permission, ?\DateTimeInterface $expiresAt = null): static
    {
        self::authorizationRoles()->grantPermission($this, $permission, $expiresAt);

        return $this;
    }

    /**
     * Spatie alias for the canonical `givePermission()` helper.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  \DateTimeInterface|null  $expiresAt
     * @return static
     *
     * @throws \Throwable
     */
    public function givePermissionTo(Permission|string $permission, ?\DateTimeInterface $expiresAt = null): static
    {
        return $this->givePermission($permission, $expiresAt);
    }

    /**
     * Detach the given permission from this role, through the role service.
     * `RolePermissionRevoked` fires only when the role carried it. A name
     * detaches every permission of that name the role carries, the current
     * tenant's and the platform's alike.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return static
     *
     * @throws \Throwable
     */
    public function revokePermission(Permission|string $permission): static
    {
        self::authorizationRoles()->revokePermission($this, $permission);

        return $this;
    }

    /**
     * Spatie alias for the canonical `revokePermission()` helper.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return static
     *
     * @throws \Throwable
     */
    public function revokePermissionTo(Permission|string $permission): static
    {
        return $this->revokePermission($permission);
    }

    /**
     * Replace this role's permission set with the supplied list, through the
     * role service.
     *
     * Each net attachment fires `RolePermissionGranted` and each net detachment
     * fires `RolePermissionRevoked`, so audit consumers receive the same
     * per-row signal they would for `givePermission()` / `revokePermission()`
     * calls and the cache invalidation listener wired to those events keeps the
     * resolution cache coherent. A permission the role carries is kept as it
     * is; one whose grant has expired is re-armed with `$expiresAt`, and a new
     * one is granted until it, or forever.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Permission|string>  $permissions
     * @param  \DateTimeInterface|null  $expiresAt
     * @return static
     *
     * @throws \Throwable
     */
    public function syncPermissions(array $permissions, ?\DateTimeInterface $expiresAt = null): static
    {
        self::authorizationRoles()->syncPermissions($this, $permissions, $expiresAt);

        return $this;
    }

    /**
     * Determine whether this role carries the given permission.
     *
     * A held permission name is treated as an `fnmatch` pattern against the
     * asked name — so a role that holds `posts:*` satisfies
     * `hasPermission('posts:create')`, and a role that holds `*` satisfies
     * every check. The reverse direction does not match: holding `posts:create`
     * does not satisfy an asked `posts:*`. Backslashes are compared literally
     * via `FNM_NOESCAPE`.
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
     * When `authorization.hierarchy.enabled` is true (the default), this
     * includes the deduplicated union of the role's own direct permissions and
     * all permissions inherited from ancestor roles. When hierarchy is
     * disabled, only directly attached permissions are returned. Either way
     * they are read in a fixed number of queries, however deep the role sits.
     *
     * @return array<int, string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public function getPermissions(): array
    {
        return RoleGraph::permissionNamesHeldBy([$this]);
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
     * Return the role service the write methods go through, as the container
     * binds it.
     *
     * @return \SineMacula\Laravel\Authorization\Services\RoleService
     *
     * @throws \LogicException
     */
    private static function authorizationRoles(): RoleService
    {
        return RoleService::instance() ?? throw new \LogicException('The authorization role service is not bound; register the package\'s service provider.');
    }
}
