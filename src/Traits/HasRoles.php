<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Traits;

use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Events\IdentityRoleAssigned;
use SineMacula\Laravel\Authorization\Events\IdentityRoleRevoked;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\AuthorizableGrantPivot;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Role membership trait for authorizable models.
 *
 * Provides assignment, revocation, synchronisation, and query helpers
 * for roles. Method names mirror the package's canonical API; Spatie
 * consumers can rely on the shipped aliases (`assignRole`,
 * `removeRole`, `syncRoles`, `hasRole`, `getRoleNames`) to migrate
 * without rewriting call sites.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 */
trait HasRoles // @phpstan-ignore trait.unused
{
    /**
     * Morph-to-many relation onto roles.
     *
     * Filters out pivot rows whose `expires_at` is in the past —
     * temporal assignments disappear from the relation
     * automatically at expiry without requiring a sweeper run.
     * The pivot's `expires_at` column is surfaced via
     * `withPivot()` so consumers can inspect remaining lifetime
     * on the cast `pivot` attribute.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Role, static>
     */
    public function roles(): MorphToMany
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $model */
        $model = config('authorization.models.role', Role::class);

        /** @var string $pivot */
        $pivot = config('authorization.tables.authorizable_roles', 'authorizable_roles');

        return $this->morphToMany(
            related: $model,
            name: 'authorizable',
            table: $pivot,
            foreignPivotKey: 'authorizable_id',
            relatedPivotKey: 'role_id',
        )
            ->using(AuthorizableGrantPivot::class)
            ->withPivot('expires_at')
            ->where(static function ($query) use ($pivot): void {
                $query->whereNull($pivot . '.expires_at')
                    ->orWhere($pivot . '.expires_at', '>', Carbon::now());
            });
    }

    /**
     * Assign the given role to this identity.
     *
     * An optional `$expiresAt` makes the grant temporal — the
     * assignment is filtered out of `$user->roles` automatically
     * the moment the clock passes the supplied instant, without
     * requiring a sweeper run. Passing null (the default) creates
     * a forever grant.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \DateTimeInterface|null  $expiresAt
     * @return static
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    public function assignRole(Role|string $role, ?\DateTimeInterface $expiresAt = null): static
    {
        $model = $this->resolveRole($role);

        $this->roles()->syncWithoutDetaching([
            (string) $model->getKey() => ['expires_at' => $expiresAt],
        ]);

        if (isset($this->relations['roles'])) {
            unset($this->relations['roles']);
        }

        Event::dispatch(new IdentityRoleAssigned($this, $model));

        return $this;
    }

    /**
     * Revoke the given role from this identity.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return static
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    public function revokeRole(Role|string $role): static
    {
        $model = $this->resolveRole($role);

        $this->roles()->detach($model->getKey());

        if (isset($this->relations['roles'])) {
            unset($this->relations['roles']);
        }

        Event::dispatch(new IdentityRoleRevoked($this, $model));

        return $this;
    }

    /**
     * Replace this identity's roles with the supplied set.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Role|string>  $roles
     * @return static
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    public function syncRoles(array $roles): static
    {
        $ids = \array_values(\array_map(
            fn (Role|string $role): string => (string) $this->resolveRole($role)->getKey(),
            $roles,
        ));

        $this->roles()->sync($ids);

        if (isset($this->relations['roles'])) {
            unset($this->relations['roles']);
        }

        // sync() bypasses assignRole / revokeRole and so fires
        // no IdentityRoleAssigned / IdentityRoleRevoked events —
        // invalidate the resolution cache directly so the next
        // getRoles() observes the fresh set.
        if (app()->bound(ResolutionCache::class)) {
            app(ResolutionCache::class)->forget($this);
        }

        return $this;
    }

    /**
     * Determine whether this identity has the given role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return bool
     */
    public function hasRole(Role|string $role): bool
    {
        $name = $role instanceof Role ? $role->name : $role;

        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Role> $roles */
        $roles = $this->roles;

        foreach ($roles as $existing) {
            if ($existing->name === $name) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the names of every role assigned to this identity.
     *
     * When the resolution cache is bound in the container, the
     * result is memoised per-request and optionally persisted
     * cross-request. Cache entries are invalidated by the
     * `InvalidateResolutionCache` listener on
     * `IdentityRoleAssigned` / `IdentityRoleRevoked`.
     *
     * @return array<int, string>
     */
    public function getRoles(): array
    {
        $cache = app()->bound(ResolutionCache::class)
            ? app(ResolutionCache::class)
            : null;

        if ($cache instanceof ResolutionCache) {
            return $cache->rememberRoles($this, fn (): array => $this->computeRoles());
        }

        return $this->computeRoles();
    }

    // ------------------------------------------------------------------
    // Spatie-compatible aliases
    // ------------------------------------------------------------------

    /**
     * Spatie alias for the canonical `revokeRole()` helper.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return static
     */
    public function removeRole(Role|string $role): static
    {
        return $this->revokeRole($role);
    }

    /**
     * Spatie alias for the canonical `getRoles()` helper.
     *
     * @return array<int, string>
     */
    public function getRoleNames(): array
    {
        return $this->getRoles();
    }

    /**
     * Resolve a role identifier to a model instance.
     *
     * Matches either an exact `guard_name` equal to the identity's
     * authorization guard or a null `guard_name` (the guard-agnostic
     * sentinel). Guard-specific rows take precedence over
     * guard-agnostic rows — the query orders non-null guards first
     * and returns the first match.
     *
     * The guard is resolved in priority order:
     *
     * 1. `$this->getAuthorizationGuard()` when the identity model
     *    declares it (the opt-in hook for multi-guard deployments —
     *    a user authenticated under `api` returns `'api'` so its
     *    assignments resolve against `api`-guard rows instead of
     *    the package default).
     * 2. `authorization.defaults.guard` otherwise.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    protected function resolveRole(Role|string $role): Role
    {
        if ($role instanceof Role) {
            return $role;
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $class */
        $class = config('authorization.models.role', Role::class);
        /** @var string $guard */
        $guard = \method_exists($this, 'getAuthorizationGuard')
            ? $this->getAuthorizationGuard()
            : config('authorization.defaults.guard', 'web');

        /** @var \SineMacula\Laravel\Authorization\Models\Role|null $model */
        $model = $class::query()
            ->where('name', $role)
            ->where(static function ($query) use ($guard): void {
                $query->where('guard_name', $guard)->orWhereNull('guard_name');
            })
            ->orderByRaw('guard_name IS NULL')
            ->first();

        if ($model === null) {
            throw new UnknownRoleException($role);
        }

        return $model;
    }

    /**
     * Compute the role-name list directly from the relation.
     *
     * @return array<int, string>
     */
    private function computeRoles(): array
    {
        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Role> $roles */
        $roles = $this->roles;

        $names = $roles->map(static fn (Role $role): string => $role->name)->all();

        return \array_values($names);
    }
}
