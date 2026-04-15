<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Traits;

use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Events\PermissionGranted;
use SineMacula\Laravel\Authorization\Events\PermissionRevoked;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Direct permission trait for authorizable models.
 *
 * Provides the `givePermission`, `revokePermission`, `syncPermissions`,
 * `hasPermission`, and `getPermissions` helpers, plus Spatie aliases
 * (`givePermissionTo`, `revokePermissionTo`, `hasPermissionTo`,
 * `getPermissionNames`) for migrating consumers. The `hasPermission`
 * check consults both direct grants and role-inherited permissions,
 * so a consumer does not need to branch on assignment style.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 */
trait HasPermissions // @phpstan-ignore trait.unused
{
    /**
     * Morph-to-many relation onto direct permissions.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Permission, static>
     */
    public function permissions(): MorphToMany
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $model */
        $model = config('authorization.models.permission', Permission::class);

        /** @var string $pivot */
        $pivot = config('authorization.tables.authorizable_permissions', 'authorizable_permissions');

        return $this->morphToMany(
            related: $model,
            name: 'authorizable',
            table: $pivot,
            foreignPivotKey: 'authorizable_id',
            relatedPivotKey: 'permission_id',
        );
    }

    /**
     * Grant the given permission directly to this identity.
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

        Event::dispatch(new PermissionGranted($this, $model));

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

        Event::dispatch(new PermissionRevoked($this, $model));

        return $this;
    }

    /**
     * Replace this identity's direct permissions with the supplied set.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Permission|string>  $permissions
     * @return static
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    public function syncPermissions(array $permissions): static
    {
        $ids = \array_values(\array_map(
            fn (Permission|string $permission): string => (string) $this->resolvePermission($permission)->getKey(),
            $permissions,
        ));

        $this->permissions()->sync($ids);

        if (isset($this->relations['permissions'])) {
            unset($this->relations['permissions']);
        }

        // sync() bypasses givePermission / revokePermission and so
        // fires no PermissionGranted / PermissionRevoked events —
        // invalidate the resolution cache directly so the next
        // getPermissions() observes the fresh set.
        if (app()->bound(ResolutionCache::class)) {
            app(ResolutionCache::class)->forget($this);
        }

        return $this;
    }

    /**
     * Determine whether the identity holds the supplied permission via
     * a direct grant or any role-inherited grant.
     *
     * A held permission name is treated as an `fnmatch` pattern
     * against the asked name — so an identity holding `posts:*`
     * satisfies `hasPermission('posts:create')`, and an identity
     * holding `*:*` satisfies every check (the super-admin path).
     * The reverse direction does not match: holding `posts:create`
     * does not satisfy an asked `posts:*`. Backslashes are compared
     * literally via `FNM_NOESCAPE`.
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
     * @return array<int, string>
     */
    public function getPermissions(): array
    {
        $cache = app()->bound(ResolutionCache::class)
            ? app(ResolutionCache::class)
            : null;

        if ($cache instanceof ResolutionCache) {
            return $cache->rememberPermissions($this, fn (): array => $this->computePermissions());
        }

        return $this->computePermissions();
    }

    /**
     * Compute the deduplicated permission-name list from the
     * direct-grant relation and every role-inherited permission.
     *
     * @return array<int, string>
     */
    private function computePermissions(): array
    {
        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission> $direct */
        $direct = $this->permissions;
        $names  = $direct->map(static fn (Permission $p): string => $p->name)->all();

        if (method_exists($this, 'roles')) {
            /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Role> $roles */
            $roles = $this->roles;

            foreach ($roles as $role) {
                /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission> $rolePermissions */
                $rolePermissions = $role->permissions;

                foreach ($rolePermissions as $rolePermission) {
                    $names[] = $rolePermission->name;
                }
            }
        }

        return \array_values(\array_unique($names));
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
     * Matches either an exact `guard_name` equal to the configured
     * default guard or a null `guard_name` (the guard-agnostic
     * sentinel). Guard-specific rows take precedence over
     * guard-agnostic rows — the query orders non-null guards first
     * and returns the first match.
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
        // Honour `$this->getAuthorizationGuard()` when the identity
        // model declares it — a user authenticated under a
        // non-default guard routes its lookups against its own
        // guard's rows instead of the package default.
        /** @var string $guard */
        $guard = \method_exists($this, 'getAuthorizationGuard')
            ? $this->getAuthorizationGuard()
            : config('authorization.defaults.guard', 'web');

        /** @var \SineMacula\Laravel\Authorization\Models\Permission|null $model */
        $model = $class::query()
            ->where('name', $permission)
            ->where(static function ($query) use ($guard): void {
                $query->where('guard_name', $guard)->orWhereNull('guard_name');
            })
            ->orderByRaw('guard_name IS NULL')
            ->first();

        if ($model === null) {
            throw new UnknownPermissionException($permission);
        }

        return $model;
    }
}
