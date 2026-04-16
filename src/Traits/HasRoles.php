<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Traits;

use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
use SineMacula\Laravel\Authorization\Events\IdentityRoleAssigned;
use SineMacula\Laravel\Authorization\Events\IdentityRoleExpiryChanged;
use SineMacula\Laravel\Authorization\Events\IdentityRoleRevoked;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\AuthorizableRolePivot;
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
    use ResolvesPivotExpiry;

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
            ->using(AuthorizableRolePivot::class)
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

        /** @var string $table */
        $table   = config('authorization.tables.authorizable_roles', 'authorizable_roles');
        $columns = self::authorizationResolveGrantPivotColumns('authorizable_roles', 'role_column', 'role_id');
        $prior   = $this->authorizationReadGrantPivot($table, $columns, (string) $model->getKey());

        $this->roles()->syncWithoutDetaching([
            (string) $model->getKey() => ['expires_at' => $expiresAt],
        ]);

        if (isset($this->relations['roles'])) {
            unset($this->relations['roles']);
        }

        Event::dispatch(new IdentityRoleAssigned($this, $model));

        if ($prior['exists'] && !self::authorizationGrantExpiriesEqual($prior['expires_at'], $expiresAt)) {
            Event::dispatch(new IdentityRoleExpiryChanged(
                $this,
                $model,
                $prior['expires_at'],
                $expiresAt,
            ));
        }

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
     * Each net attachment fires `IdentityRoleAssigned` and each
     * net detachment fires `IdentityRoleRevoked`, so audit
     * consumers receive the same per-row signal they would for
     * `assignRole()` / `revokeRole()` calls and the cache
     * invalidation listener wired to those events keeps the
     * resolution cache coherent without a separate forget call
     * in this method.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Role|string>  $roles
     * @return static
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    public function syncRoles(array $roles): static
    {
        $resolved = [];

        foreach ($roles as $role) {
            $model                               = $this->resolveRole($role);
            $resolved[(string) $model->getKey()] = $model;
        }

        $ids    = \array_keys($resolved);
        $result = $this->roles()->sync($ids);

        if (isset($this->relations['roles'])) {
            unset($this->relations['roles']);
        }

        /** @var array{attached?: array<int, mixed>, detached?: array<int, mixed>, updated?: array<int, mixed>} $result */
        foreach ($result['attached'] ?? [] as $id) {
            Event::dispatch(new IdentityRoleAssigned($this, $resolved[(string) $id] ?? $this->resolveRoleById((string) $id)));
        }

        foreach ($result['detached'] ?? [] as $id) {
            Event::dispatch(new IdentityRoleRevoked($this, $this->resolveRoleById((string) $id)));
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
     * `IdentityRoleAssigned` / `IdentityRoleRevoked` (and — on a
     * tag-capable persistent store — on
     * `RolePermissionGranted` / `RolePermissionRevoked` via role
     * tags). The persistent-tier TTL is additionally bounded by
     * the nearest upcoming `expires_at` across the relation's
     * pivot rows so temporal grants invalidate themselves at the
     * exact moment they lapse (#77).
     *
     * @return array<int, string>
     */
    public function getRoles(): array
    {
        $cache = ResolutionCache::instance();

        if ($cache instanceof ResolutionCache) {
            /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Role> $roles */
            $roles   = $this->roles;
            $roleIds = self::authorizationCollectModelIds($roles);
            $maxTtl  = self::authorizationNearestPivotExpirySeconds($roles);

            return $cache->rememberRoles(
                $this,
                fn (): array => $this->computeRoles(),
                new ResolutionCacheContext(maxTtl: $maxTtl, roleIds: $roleIds),
            );
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
     * Honours `$this->getAuthorizationGuard()` when the identity
     * model declares it — a user authenticated under a non-default
     * guard routes its lookups against its own guard's rows instead
     * of the package default. Delegates the actual query to
     * `Role::resolveByName()` so both identity-side and any other
     * caller share one implementation (see #96).
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

        $guard = \method_exists($this, 'getAuthorizationGuard')
            ? $this->getAuthorizationGuard()
            : null;

        return $class::resolveByName($role, $guard);
    }

    /**
     * Resolve a role model by primary key, used by `syncRoles()`
     * when the sync delta surfaces an ID that was not part of the
     * caller's input set (the detachment list).
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    private function resolveRoleById(string $id): Role
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $class */
        $class = config('authorization.models.role', Role::class);

        /** @var \SineMacula\Laravel\Authorization\Models\Role|null $model */
        $model = $class::query()->whereKey($id)->first();

        if ($model === null) {
            throw new UnknownRoleException($id);
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
