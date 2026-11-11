<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\RankComparison;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Models\Pivots\AuthorizableRolePivot;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\GrantResolver;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Role membership trait for authorizable models.
 *
 * Provides assignment, revocation, synchronisation, and query helpers for
 * roles. Method names mirror the package's canonical API; Spatie consumers can
 * rely on the shipped aliases (`assignRole`, `removeRole`, `syncRoles`,
 * `hasRole`, `getRoleNames`) to migrate without rewriting call sites.
 *
 * Each write helper takes an optional `actor:`, an acting context it hands to
 * the service, so the change is delegated and decided as that actor
 * (AUTHZ-11.1). Without one it is trusted system work: nothing is decided, so a
 * helper called without an actor is an integration surface for the
 * application's own code, never an endpoint for user-controlled administration.
 * `removeRole()` takes no actor, so it is always trusted.
 *
 * The role checks and `canActOn()` refuse while the package is not healthy (see
 * `PackageState`), before the resolution cache or the loaded roles are read.
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
     * `pivot` attribute, and the grant's timestamps are kept. Only the grants
     * that hold in the current tenant and application count.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Role,
     *     $this, \SineMacula\Laravel\Authorization\Models\Pivots\AuthorizableRolePivot, 'pivot'>
     */
    public function roles(): MorphToMany
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $model */
        $model = ModelClasses::get('role');

        $table = TableNames::get('authorizable_roles');

        return $this->authorizationGrantRelation($model, $table, 'role_id', AuthorizableRolePivot::class);
    }

    /**
     * Assign the given role to this identity, through the grant service.
     *
     * An optional `$expiresAt` makes the grant temporal — the assignment is
     * filtered out of `$user->roles` automatically the moment the clock passes
     * the supplied instant, without requiring a sweeper run. Passing null (the
     * default) creates a forever grant. Assigning a role the identity holds
     * with the same expiry and reach changes nothing and dispatches no event; a
     * role whose grant has expired is re-armed with the new expiry.
     *
     * A grant in a tenant also holds in the tenants below it in the tenant
     * tree, unless `$includeSubtree` is false.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return static
     *
     * @throws \Throwable
     */
    public function assignRole(
        Role|string $role,
        ?\DateTimeInterface $expiresAt = null,
        Model|Reference|null $tenant = null,
        bool $includeSubtree = true,
        ?string $application = null,
        ?ActingContext $actor = null,
    ): static {
        self::authorizationGrants()->grantRole($this, $role, $expiresAt, $actor, $tenant, $includeSubtree, $application);

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
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return static
     *
     * @throws \Throwable
     */
    public function revokeRole(Role|string $role, Model|Reference|null $tenant = null, ?string $application = null, ?ActingContext $actor = null): static
    {
        self::authorizationGrants()->revokeRole($this, $role, $actor, $tenant, $application);

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
     * In a tenant, a role is granted reaching the tenants below it. An entry
     * may give a role its own reach, as `RoleReach::of('billing',
     * includeSubtree: false)`, so one sync holds roles of both reaches; a role
     * listed so and held live with the other reach has its reach changed in
     * place, keeping its expiry, and `RoleAssigned` fires for it (see
     * `GrantService::syncRoles()`).
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Role|\SineMacula\Laravel\Authorization\Support\RoleReach|string>  $roles
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return static
     *
     * @throws \Throwable
     */
    public function syncRoles(array $roles, Model|Reference|null $tenant = null, ?string $application = null, ?ActingContext $actor = null): static
    {
        self::authorizationGrants()->syncRoles($this, $roles, actor: $actor, tenant: $tenant, application: $application);

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
     * Only roles granted in the current tenant, or platform-wide, count. They
     * are read once per model instance, under the tenant current then, as
     * Eloquent keeps any loaded relation; the tenant is held for a request or
     * job, so a model read in that request or job sees its tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  string|null  $guard
     * @return bool
     */
    public function hasRole(Role|string $role, ?string $guard = null): bool
    {
        PackageState::guardCurrent();

        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Role> $roles */
        $roles = $this->authorizationLoadedGrants('roles');

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
     * The names are read through the resolution cache: memoised for the request
     * or job, and kept in the persistent store when one is configured, for no
     * longer than the nearest grant expiry or the configured maximum. A grant,
     * revocation or change to a held role takes effect on the next check.
     *
     * @return array<int, string>
     */
    public function getRoles(): array
    {
        PackageState::guardCurrent();

        $resolve = fn (ResolutionPins $pins): Resolution => GrantResolver::roles($this->roles(), $pins);

        return ResolutionCache::instance()?->rememberRoles($this, $resolve) ?? $resolve(new ResolutionPins)->value;
    }

    // ------------------------------------------------------------------ Rank
    // helpers
    // ------------------------------------------------------------------

    /**
     * Determine whether rank lets this identity act on the given target, as
     * `RankComparison` compares them (N76): strictly senior, an unranked target
     * the most junior, an unranked actor acting on no one, and either side
     * whose roles cannot be read not comparable. Both are resolved the same
     * way, in the current tenant and application, an expired grant never
     * counting. With `authorization.rank.enabled` false, rank is no constraint,
     * so it returns true.
     *
     * It returns the comparison alone and grants nothing: rank is never an
     * allow (AUTHZ-3.5), and delegated administration weighs it beside every
     * other check, never in place of one.
     *
     * @param  object  $target
     * @return bool
     */
    public function canActOn(object $target): bool
    {
        PackageState::guardCurrent();

        return RankComparison::canActOn($this, $target);
    }

    // ------------------------------------------------------------------
    // Spatie-compatible aliases
    // ------------------------------------------------------------------

    /**
     * Spatie alias for the canonical `revokeRole()` helper, handing the acting
     * context, when there is one, on.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return static
     *
     * @throws \Throwable
     */
    public function removeRole(Role|string $role, ?ActingContext $actor = null): static
    {
        return $this->revokeRole($role, actor: $actor);
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
}
