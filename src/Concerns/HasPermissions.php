<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Support\Collection;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Pivots\AuthorizablePermissionPivot;
use SineMacula\Laravel\Authorization\Resolvers\GrantResolver;
use SineMacula\Laravel\Authorization\Support\HeldPermissions;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Direct permission trait for authorizable models.
 *
 * Provides the `givePermission`, `revokePermission`, `syncPermissions`,
 * `hasPermission`, and `getPermissions` helpers, plus Spatie aliases
 * (`givePermissionTo`, `revokePermissionTo`, `hasPermissionTo`,
 * `getPermissionNames`) for migrating consumers. The `hasPermission` check
 * consults both direct grants and role-inherited permissions, so a consumer
 * does not need to branch on assignment style. `canEach` and `filterAuthorized`
 * decide the model's checks over many resources through the authorization
 * manager.
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
     * `withPivot()`, and the grant's timestamps are kept. Only the grants that
     * hold in the current tenant and application count.
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

        /** @var string $table */
        $table = config('authorization.tables.authorizable_permissions', 'authorizable_permissions');

        return $this->authorizationGrantRelation($model, $table, 'permission_id', AuthorizablePermissionPivot::class);
    }

    /**
     * Grant the given permission directly to this identity, through the grant
     * service.
     *
     * An optional `$expiresAt` makes the grant temporal — the attachment is
     * filtered out of `$user->permissions` the moment the clock passes the
     * supplied instant, without requiring a sweeper run. Passing null (the
     * default) creates a forever grant. Granting a permission the identity
     * holds with the same expiry and reach changes nothing and dispatches no
     * event; a permission whose grant has expired is re-armed with the new
     * expiry.
     *
     * A grant in a tenant also holds in the tenants below it in the tenant
     * tree, unless `$includeSubtree` is false.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
     * @return static
     *
     * @throws \Throwable
     */
    public function givePermission(
        Permission|string $permission,
        ?\DateTimeInterface $expiresAt = null,
        Model|Reference|null $tenant = null,
        bool $includeSubtree = true,
        ?string $application = null,
    ): static {
        self::authorizationGrants()->grantPermission($this, $permission, $expiresAt, null, $tenant, $includeSubtree, $application);

        return $this;
    }

    /**
     * Revoke a directly granted permission, through the grant service.
     *
     * A name is revoked from the grants the identity holds, not from the one
     * row a lookup would pick: every held permission of that name for the
     * identity's guard, or guard-agnostic, is detached, whether the current
     * tenant or the platform owns it, so a tenant's permission of the same name
     * never hides the platform grant. `IdentityPermissionRevoked` fires once
     * for each permission really detached, and not at all when the identity
     * held none.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @return static
     *
     * @throws \Throwable
     */
    public function revokePermission(Permission|string $permission, Model|Reference|null $tenant = null, ?string $application = null): static
    {
        self::authorizationGrants()->revokePermission($this, $permission, null, $tenant, $application);

        return $this;
    }

    /**
     * Replace this identity's direct permissions with the supplied set, through
     * the grant service.
     *
     * Each net attachment fires `IdentityPermissionGranted` and each net
     * detachment fires `IdentityPermissionRevoked`, so audit consumers receive
     * the same per-row signal they would for `givePermission()` /
     * `revokePermission()` calls and the cache invalidation listener wired to
     * those events keeps the resolution cache coherent without a separate
     * forget call in this method. A listed permission whose grant has expired
     * is re-armed with no expiry; to re-arm it for a limited time, call
     * `GrantService::syncPermissions()` with an expiry.
     *
     * A name keeps every held permission of that name, whether the current
     * tenant or the platform owns it, and only when the identity holds none is
     * the permission the lookup ranks first attached, so a tenant's permission
     * of the same name never replaces a platform grant.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Permission|string>  $permissions
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @return static
     *
     * @throws \Throwable
     */
    public function syncPermissions(array $permissions, Model|Reference|null $tenant = null, ?string $application = null): static
    {
        self::authorizationGrants()->syncPermissions($this, $permissions, tenant: $tenant, application: $application);

        return $this;
    }

    /**
     * Determine whether the identity holds the supplied permission via a direct
     * grant or any role-inherited grant.
     *
     * A held permission name is treated as an `fnmatch` pattern against the
     * asked name — so an identity holding `posts:*` satisfies
     * `hasPermission('posts:create')`, and an identity holding `*` satisfies
     * every check (the super-admin path). The reverse direction does not match:
     * holding `posts:create` does not satisfy an asked `posts:*`. Backslashes
     * are compared literally via `FNM_NOESCAPE` (see `HeldPermissions`).
     *
     * This reports what is granted in the current scope (the tenant chain and
     * application the tenant scope applies), and decides nothing: it weighs no
     * policy, deny, guardrail, boundary or session cap, and no resource's
     * tenant. To ask whether the subject may perform an action, decide it with
     * `Authorization::check()` or `can()`, through which the Gate, the Blade
     * permission directives, the `permission:` middleware and
     * `effectivePermissions()` all decide.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return bool
     */
    public function hasPermission(Permission|string $permission): bool
    {
        $asked = $permission instanceof Permission ? $permission->name : $permission;

        return HeldPermissions::match($this->getPermissions(), $asked) !== null;
    }

    /**
     * Return the union of direct and role-inherited permission names, with the
     * permissions of each role's ancestors when the hierarchy is enabled.
     *
     * The names are read through the resolution cache: memoised for the request
     * or job, and kept in the persistent store when one is configured, for no
     * longer than the nearest grant expiry or the configured maximum. A grant,
     * revocation or change to a held role, its ancestors or a held permission
     * takes effect on the next check. A miss takes five queries however many
     * roles the identity holds and however deep they sit.
     *
     * Only the grants that reach the current scope count: platform-wide ones,
     * those made in the current tenant, and its ancestors' that reach the
     * tenants below them, in the current application or every one, and not
     * expired (see `TenantChain::grants()`). Each scope's names are resolved
     * and kept apart, under the scope's tenant and application, so the
     * resolutions form a map from scope to the permissions that reach it: a
     * check on a resource of a tenant reads the map's entry for that tenant
     * (see `ResourceScope`), and a grant never counts where it does not reach.
     *
     * @return array<int, string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public function getPermissions(): array
    {
        $resolve = fn (ResolutionPins $pins): Resolution => GrantResolver::permissions($this->permissions(), $this->roles(), $pins);

        return ResolutionCache::instance()?->rememberPermissions($this, $resolve) ?? $resolve(new ResolutionPins)->value;
    }

    /**
     * Determine, for each resource, whether this model is allowed the action on
     * it, keyed as the resources are: a delegate to
     * `Authorization::for($this)->canEach()`, deciding every resource through
     * the full decision, policies, boundaries, guardrails and caps included.
     *
     * @template TKey of array-key
     *
     * @param  string  $action
     * @param  iterable<TKey, mixed>  $resources
     * @param  array<string, mixed>  $context
     * @return array<TKey, bool>
     */
    public function canEach(string $action, iterable $resources, array $context = []): array
    {
        return Authorization::for($this)->canEach($action, $resources, $context);
    }

    /**
     * Return the resources this model is allowed the action on, with their
     * keys, in their order, as given: a delegate to
     * `Authorization::for($this)->filterAuthorized()`, deciding every resource
     * through the full decision, policies, boundaries, guardrails and caps
     * included.
     *
     * @param  string  $action
     * @param  iterable<array-key, mixed>  $resources
     * @param  array<string, mixed>  $context
     * @return ($resources is \Illuminate\Support\Collection<array-key, mixed> ? \Illuminate\Support\Collection<array-key, mixed> : array<array-key, mixed>)
     */
    public function filterAuthorized(string $action, iterable $resources, array $context = []): array|Collection
    {
        return Authorization::for($this)->filterAuthorized($action, $resources, $context);
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
}
