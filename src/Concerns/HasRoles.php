<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use Illuminate\Database\Eloquent\Relations\MorphToMany;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
use SineMacula\Laravel\Authorization\Models\Pivots\AuthorizableRolePivot;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Role membership trait for authorizable models.
 *
 * Provides assignment, revocation, synchronisation, and query helpers for
 * roles. Method names mirror the package's canonical API; Spatie consumers can
 * rely on the shipped aliases (`assignRole`, `removeRole`, `syncRoles`,
 * `hasRole`, `getRoleNames`) to migrate without rewriting call sites.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authorization\Contracts\SupportsRoles
 */
trait HasRoles // @phpstan-ignore trait.unused
{
    use ResolvesPivotExpiry;

    /**
     * Morph-to-many relation onto roles.
     *
     * Filters out pivot rows whose `expires_at` is in the past — temporal
     * assignments disappear from the relation automatically at expiry without
     * requiring a sweeper run. The pivot's `expires_at` column is surfaced via
     * `withPivot()` so consumers can inspect remaining lifetime on the cast
     * `pivot` attribute, and the grant's timestamps are kept. The scope columns
     * keep their defaults: every grant made here is platform-wide, for every
     * application.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Role,
     *     $this, \SineMacula\Laravel\Authorization\Models\Pivots\AuthorizableRolePivot, 'pivot'>
     */
    public function roles(): MorphToMany
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $model */
        $model = config('authorization.models.role', Role::class);

        /** @var string $table */
        $table = config('authorization.tables.authorizable_roles', 'authorizable_roles');

        return $this->authorizationGrantRelation($model, $table, 'role_id', AuthorizableRolePivot::class);
    }

    /**
     * Assign the given role to this identity, through the grant service.
     *
     * An optional `$expiresAt` makes the grant temporal — the assignment is
     * filtered out of `$user->roles` automatically the moment the clock passes
     * the supplied instant, without requiring a sweeper run. Passing null (the
     * default) creates a forever grant. Assigning a role the identity holds
     * with the same expiry changes nothing and dispatches no event; a role
     * whose grant has expired is re-armed with the new expiry.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \DateTimeInterface|null  $expiresAt
     * @return static
     *
     * @throws \Throwable
     */
    public function assignRole(Role|string $role, ?\DateTimeInterface $expiresAt = null): static
    {
        self::authorizationGrants()->grantRole($this, $role, $expiresAt);

        return $this;
    }

    /**
     * Revoke the given role from this identity, through the grant service.
     *
     * A name is revoked from the grants the identity holds, not from the one
     * row a lookup would pick: every held role of that name for the identity's
     * guard, or guard-agnostic, is detached, whether the current tenant or the
     * platform owns it, so a tenant's role of the same name never hides the
     * platform grant. `IdentityRoleRevoked` fires once for each role really
     * detached, and not at all when the identity held none.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return static
     *
     * @throws \Throwable
     */
    public function revokeRole(Role|string $role): static
    {
        self::authorizationGrants()->revokeRole($this, $role);

        return $this;
    }

    /**
     * Replace this identity's roles with the supplied set, through the grant
     * service.
     *
     * Each net attachment fires `IdentityRoleAssigned` and each net detachment
     * fires `IdentityRoleRevoked`, so audit consumers receive the same per-row
     * signal they would for `assignRole()` / `revokeRole()` calls and the cache
     * invalidation listener wired to those events keeps the resolution cache
     * coherent without a separate forget call in this method. A listed role
     * whose grant has expired is re-armed with no expiry; to re-arm it for a
     * limited time, call `GrantService::syncRoles()` with an expiry.
     *
     * A name keeps every held role of that name, whether the current tenant or
     * the platform owns it, and only when the identity holds none is the role
     * the lookup ranks first attached, so a tenant's role of the same name
     * never replaces a platform grant.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Role|string>  $roles
     * @return static
     *
     * @throws \Throwable
     */
    public function syncRoles(array $roles): static
    {
        self::authorizationGrants()->syncRoles($this, $roles);

        return $this;
    }

    /**
     * Determine whether this identity has the given role.
     *
     * A role model matches only that row, by primary key, so a tenant's role
     * that shares the name of a platform role never passes a check for the
     * platform's. A name matches any held role of that name the tenant scope
     * shows, the platform's or the current tenant's; a tenant cannot take the
     * name of a platform system role (see `RoleObserver`), so a name check for
     * a system role is only ever met by the system role itself. With a guard,
     * only a held role of that guard or of no guard counts.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  string|null  $guard
     * @return bool
     */
    public function hasRole(Role|string $role, ?string $guard = null): bool
    {
        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Role> $roles */
        $roles = $this->roles;

        foreach ($roles as $existing) {
            $named = $role instanceof Role ? $existing->is($role) : $existing->name === $role;

            if ($named && ($guard === null || $existing->guard === null || $existing->guard === $guard)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the names of every role assigned to this identity.
     *
     * When the resolution cache is bound in the container, the result is
     * memoised per-request and optionally persisted cross-request. Cache
     * entries are invalidated by the `InvalidateResolutionCache` listener on
     * `IdentityRoleAssigned` / `IdentityRoleRevoked` (and — on a tag-capable
     * persistent store — on `RolePermissionGranted` / `RolePermissionRevoked`
     * via role tags). The persistent-tier TTL is additionally bounded by the
     * nearest upcoming `expires_at` across the relation's pivot rows so
     * temporal grants invalidate themselves at the exact moment they lapse.
     * Once the in-memory entry has lapsed the relation is reloaded, so a reused
     * instance does not rebuild the entry from the roles it loaded before.
     *
     * @return array<int, string>
     */
    public function getRoles(): array
    {
        $cache = ResolutionCache::instance();

        if ($cache instanceof ResolutionCache) {
            if ($cache->lapsed('roles', $this)) {
                $this->unsetRelation('roles');
            }

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
    // Rank helpers
    // ------------------------------------------------------------------

    /**
     * Determine whether this identity can act on the given target based on role
     * rank seniority.
     *
     * Both `$this` and `$target` must implement `SupportsRoles`;
     * returns false otherwise. When `authorization.rank.enabled` is false the
     * check is bypassed and the method returns true unconditionally (rank
     * feature disabled).
     *
     * Semantics:
     * - Actor has no ranked roles -> false (cannot assert rank authority).
     * - Target has no ranked roles -> true (unranked targets are freely
     *   actable-on).
     * - Otherwise: actor's best rank must be strictly less than target's best
     *   rank (strict-senior — equal rank = cannot act).
     *
     * @param  object  $target
     * @return bool
     */
    public function canActOn(object $target): bool
    {
        /** @var bool $enabled */
        $enabled = config('authorization.rank.enabled', true);

        if (!$enabled) {
            return true;
        }

        $actorRank = $this instanceof SupportsRoles ? $this->highestRank() : null;

        if ($actorRank === null || !($target instanceof SupportsRoles) || !\method_exists($target, 'roles')) {
            return false;
        }

        $targetRank = $this->computeHighestRank($target->roles()->get());

        return $targetRank === null || $actorRank < $targetRank;
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

    /**
     * Return the lowest `rank` value across this identity's roles, or null if
     * none of the assigned roles are ranked.
     *
     * Lower rank = more senior (0 is the most senior).
     *
     * @return int|null
     */
    private function highestRank(): ?int
    {
        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Role> $roles */
        $roles = $this->roles;

        return $this->computeHighestRank($roles);
    }

    /**
     * Scan a collection of roles and return the lowest `rank` value (most
     * senior), or null when no role in the set is ranked.
     *
     * @param  iterable<int, \SineMacula\Laravel\Authorization\Models\Role>  $roles
     * @return int|null
     */
    private function computeHighestRank(iterable $roles): ?int
    {
        $best = null;

        foreach ($roles as $role) {
            if ($role->rank === null) {
                continue;
            }

            if ($best !== null && $role->rank >= $best) {
                continue;
            }

            $best = $role->rank;
        }

        return $best;
    }
}
