<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionExpiryChanged as IdentityPermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionGranted as IdentityPermissionGranted;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionRevoked as IdentityPermissionRevoked;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Pivots\AuthorizablePermissionPivot;

/**
 * Direct permission trait for authorizable models.
 *
 * Provides the `givePermission`, `revokePermission`, `syncPermissions`,
 * `hasPermission`, and `getPermissions` helpers, plus Spatie aliases
 * (`givePermissionTo`, `revokePermissionTo`, `hasPermissionTo`,
 * `getPermissionNames`) for migrating consumers. The `hasPermission` check
 * consults both direct grants and role-inherited permissions, so a consumer
 * does not need to branch on assignment style.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authorization\Contracts\SupportsRoles
 */
trait HasPermissions // @phpstan-ignore trait.unused
{
    use ResolvesPivotExpiry;

    /**
     * Morph-to-many relation onto direct permissions.
     *
     * Filters out pivot rows whose `expires_at` is in the past — temporal
     * grants disappear from the relation automatically at expiry without
     * requiring a sweeper run. The pivot's `expires_at` column is surfaced via
     * `withPivot()`.
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Permission, $this,
     *     \SineMacula\Laravel\Authorization\Models\Pivots\AuthorizablePermissionPivot, 'pivot'>
     *
     * @formatter:on
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     */
    public function permissions(): MorphToMany
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $model */
        $model = config('authorization.models.permission', Permission::class);

        /** @var string $pivot */
        $pivot = config('authorization.tables.authorizable_permissions', 'authorizable_permissions');

        // The `where(...)` and inner `whereNull()/orWhere()` calls are resolved
        // by PHPStan to static methods on Eloquent's Builder via Laravel's
        // annotation soup — the underlying dispatch is instance-level. Same
        // pattern, same justification, as `GuardScopedLookup`.
        // @phpstan-ignore staticMethod.dynamicCall
        return $this->morphToMany(
            related: $model,
            name: 'authorizable',
            table: $pivot,
            foreignPivotKey: 'authorizable_id',
            relatedPivotKey: 'permission_id',
        )
            ->using(AuthorizablePermissionPivot::class)
            ->withPivot('expires_at')
            ->where(static function (Builder $query) use ($pivot): void {
                // @phpstan-ignore staticMethod.dynamicCall
                $query->whereNull($pivot . '.expires_at')
                    ->orWhere($pivot . '.expires_at', '>', Carbon::now());
            });
    }

    /**
     * Grant the given permission directly to this identity.
     *
     * An optional `$expiresAt` makes the grant temporal — the attachment is
     * filtered out of `$user->permissions` the moment the clock passes the
     * supplied instant, without requiring a sweeper run. Passing null (the
     * default) creates a forever grant.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  \DateTimeInterface|null  $expiresAt
     * @return static
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    public function givePermission(Permission|string $permission, ?\DateTimeInterface $expiresAt = null): static
    {
        $model = $this->resolvePermission($permission);

        /** @var string $table */
        $table   = config('authorization.tables.authorizable_permissions', 'authorizable_permissions');
        $columns = self::authorizationResolveGrantPivotColumns('authorizable_permissions', 'permission_column', 'permission_id');
        $prior   = self::authorizationReadGrantPivot($this, $table, $columns, (string) $model->getKey());

        $this->permissions()->syncWithoutDetaching([
            (string) $model->getKey() => ['expires_at' => $expiresAt],
        ]);

        if (isset($this->relations['permissions'])) {
            unset($this->relations['permissions']);
        }

        Event::dispatch(new IdentityPermissionGranted($this, $model));

        if ($prior['exists'] && !self::areAuthorizationGrantExpiriesEqual($prior['expires_at'], $expiresAt)) {
            Event::dispatch(new IdentityPermissionExpiryChanged(
                $this,
                $model,
                $prior['expires_at'],
                $expiresAt,
            ));
        }

        return $this;
    }

    /**
     * Revoke a directly granted permission.
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

        Event::dispatch(new IdentityPermissionRevoked($this, $model));

        return $this;
    }

    /**
     * Replace this identity's direct permissions with the supplied set.
     *
     * Each net attachment fires `IdentityPermissionGranted` and each net
     * detachment fires `IdentityPermissionRevoked`, so audit consumers receive
     * the same per-row signal they would for `givePermission()` /
     * `revokePermission()` calls and the cache invalidation listener wired to
     * those events keeps the resolution cache coherent without a separate
     * forget call in this method.
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
            $model                               = $this->resolvePermission($permission);
            $resolved[(string) $model->getKey()] = $model;
        }

        $ids    = \array_keys($resolved);
        $result = $this->permissions()->sync($ids);

        if (isset($this->relations['permissions'])) {
            unset($this->relations['permissions']);
        }

        foreach ($result['attached'] as $id) {
            Event::dispatch(new IdentityPermissionGranted($this, $resolved[(string) $id] ?? $this->resolvePermissionById((string) $id)));
        }

        foreach ($result['detached'] as $id) {
            Event::dispatch(new IdentityPermissionRevoked($this, $this->resolvePermissionById((string) $id)));
        }

        return $this;
    }

    /**
     * Determine whether the identity holds the supplied permission via a direct
     * grant or any role-inherited grant.
     *
     * A held permission name is treated as an `fnmatch` pattern against the
     * asked name — so an identity holding `posts:*` satisfies
     * `hasPermission('posts:create')`, and an identity holding `*:*` satisfies
     * every check (the super-admin path). The reverse direction does not match:
     * holding `posts:create` does not satisfy an asked `posts:*`. Backslashes
     * are compared literally via `FNM_NOESCAPE`.
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
     * Return the union of direct and role-inherited permission names.
     *
     * The persistent-tier TTL is bounded by the nearest upcoming `expires_at`
     * across both the identity's direct permission pivot and its role pivot, so
     * temporal grants on either side invalidate the entry at the moment they
     * lapse. The role IDs are tagged into the entry so a
     * `RolePermissionGranted` / `RolePermissionRevoked` event flushes every
     * principal carrying the mutated role on tag-capable stores.
     *
     * @return array<int, string>
     */
    public function getPermissions(): array
    {
        $cache = ResolutionCache::instance();

        if ($cache instanceof ResolutionCache) {
            /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission> $direct */
            $direct = $this->permissions;

            /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Role> $roles */
            $roles   = $this->roles;
            $roleIds = self::authorizationCollectModelIds($roles);

            $nearest = self::authorizationNearestPivotExpirySeconds($direct);
            $nearest = self::authorizationMinNullable($nearest, self::authorizationNearestPivotExpirySeconds($roles));

            return $cache->rememberPermissions(
                $this,
                fn (): array => $this->computePermissions(),
                new ResolutionCacheContext(maxTtl: $nearest, roleIds: $roleIds),
            );
        }

        return $this->computePermissions();
    }

    // ------------------------------------------------------------------
    // Spatie-compatible aliases
    // ------------------------------------------------------------------

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
     * Honours `$this->getAuthorizationGuard()` when the identity model declares
     * it — a user authenticated under a non-default guard routes its lookups
     * against its own guard's rows instead of the package default. Delegates
     * the actual query to `Permission::resolveByName()` so both identity-side
     * and role-side lookups share one implementation.
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

        return $class::resolveByName($permission, self::authorizationResolveGuard($this));
    }

    /**
     * Resolve a permission model by primary key, used by `syncPermissions()`
     * when the sync delta surfaces an ID that was not part of the caller's
     * input set (the detachment list).
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

    /**
     * Compute the deduplicated permission-name list from the direct-grant
     * relation and every role-inherited permission.
     *
     * @return array<int, string>
     */
    private function computePermissions(): array
    {
        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission> $direct */
        $direct = $this->permissions;
        $names  = $direct->map(static fn (Permission $p): string => $p->name)->all();

        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Role> $roles */
        $roles = $this->roles;

        foreach ($roles as $role) {
            foreach ($role->getPermissions() as $rolePerm) {
                $names[] = $rolePerm;
            }
        }

        return \array_values(\array_unique($names));
    }
}
