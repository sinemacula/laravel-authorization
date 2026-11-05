<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Scopes;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Scope;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;

/**
 * Global query scope for row-level multi-tenant filtering.
 *
 * When the subject the `SubjectResolver` returns has a tenant, this scope
 * restricts queries to rows that are either platform-wide (null tenant columns)
 * or owned by that tenant. When there is no subject, or the subject has no
 * tenant, only platform-wide rows remain visible: a missing tenant never makes
 * every tenant's rows visible.
 *
 * The scope keeps no tenant of its own. It reads the tenant from the
 * `ResolvedTenant` holder, which the service provider binds with `scoped()`, so
 * a single request or job (the `effectivePermissions()` enum sweep, relation
 * walks, cache-miss paths) pays the resolver cost once, and the next request or
 * job resolves its own tenant. While a resolution is under way it marks it in
 * the container, rather than on the scope, since each scoped model holds its
 * own instance of the scope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Database\Eloquent\Scope<\Illuminate\Database\Eloquent\Model>
 */
final class TenantScope implements Scope
{
    /** @var string The container key bound while the subject's tenant is being resolved, so a query on any scoped model the resolver runs meanwhile sees platform rows only. */
    private const string RESOLVING = 'authorization.tenant_scope.resolving';

    /**
     * Apply the tenant scope to the given Eloquent builder.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>  $builder
     * @param  \Illuminate\Database\Eloquent\Model  $model
     *
     * @phpstan-param \Illuminate\Database\Eloquent\Builder<covariant \Illuminate\Database\Eloquent\Model> $builder
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    #[\Override]
    public function apply(Builder $builder, Model $model): void
    {
        $typeColumn = $model->getTable() . '.tenant_type';
        $idColumn   = $model->getTable() . '.tenant_id';
        $tenant     = self::currentTenant();

        // `whereNull` / `orWhere` are declared as `@method static` on the
        // Eloquent Builder docblock; PHPStan flags dynamic instance calls as
        // `staticMethod.dynamicCall` even though runtime dispatch is genuinely
        // dynamic. The same pattern is used in `GuardScopedLookup` —
        // docblock-soup artefacts, not unsafe calls.
        if ($tenant === null) {
            // @phpstan-ignore staticMethod.dynamicCall
            $builder->whereNull($typeColumn);

            return;
        }

        [$morphType, $morphId] = $tenant;

        // @phpstan-ignore staticMethod.dynamicCall
        $builder->where(function ($q) use ($typeColumn, $idColumn, $morphType, $morphId): void {
            // @phpstan-ignore staticMethod.dynamicCall
            $q->whereNull($typeColumn)
                ->orWhere(function ($q2) use ($typeColumn, $idColumn, $morphType, $morphId): void {
                    $q2->where($typeColumn, $morphType)
                        ->where($idColumn, $morphId);
                });
        });
    }

    /**
     * Return the morph type and key of the tenant the scope limits rows to, or
     * null when it limits them to the platform's.
     *
     * The resolution cache keys its entries by it, since the roles and
     * permissions an identity resolves to depend on it.
     *
     * @return array{0: string, 1: string}|null
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    public static function currentTenant(): ?array
    {
        $tenant = self::resolveTenant();

        return $tenant === null ? null : self::extractTenantPair($tenant);
    }

    /**
     * Extract the `(tenant_type, tenant_id)` pair from an arbitrary tenant
     * object, refusing anything that cannot supply a stable pair without a
     * `spl_object_hash`-style fallback.
     *
     * A tenant without a key (an unsaved model, or an `AuthorizableTenant`
     * returning an empty string) is refused as well: its pair would be
     * `tenant_id = ''`, which matches no row it owns.
     *
     * Shared by the global scope, the grant service and the current tenant's
     * lookup so the acceptance rules have a single owner.
     *
     * @param  object  $tenant
     * @return array{0: string, 1: string}
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    public static function extractTenantPair(object $tenant): array
    {
        if (!$tenant instanceof Model && !$tenant instanceof AuthorizableTenant) {
            throw new InvalidTenantException($tenant);
        }

        /** @var int|string|null $key */
        $key = $tenant->getKey();

        if ($key === null || $key === '') {
            throw InvalidTenantException::withoutKey($tenant);
        }

        return [$tenant->getMorphClass(), (string) $key];
    }

    /**
     * Drop the tenant resolved for the current request or job, so the next
     * query asks the resolver again. Exposed for consumers that pivot the
     * current tenant mid-request (for example an admin console that switches
     * context) without rebinding the resolver. The resolution cache's memo,
     * resolved under the dropped tenant, is emptied with it.
     *
     * @return void
     */
    public function flushResolvedTenant(): void
    {
        Container::getInstance()->forgetInstance(ResolvedTenant::class);

        ResolutionCache::instance()?->tenantChanged();
    }

    /**
     * Return the tenant resolved for the current request or job, or null for a
     * query run while the subject is being resolved.
     *
     * Resolving the subject can itself query a scoped model: the shipped
     * resolver reads the signed-in user, and a user model that eager-loads its
     * roles and permissions queries them. Those queries, on any scoped model,
     * see platform rows only, so the resolver runs once rather than again for
     * each model, or without end.
     *
     * @return object|null
     */
    private static function resolveTenant(): ?object
    {
        $container = Container::getInstance();

        if ($container->bound(self::RESOLVING)) {
            return null;
        }

        $container->instance(self::RESOLVING, true);

        try {
            return self::readResolvedTenant($container);
        } finally {
            $container->forgetInstance(self::RESOLVING);
        }
    }

    /**
     * Return the tenant resolved for the current request or job, resolving it
     * again when the bound resolver is not the one it was read from.
     *
     * @param  \Illuminate\Container\Container  $container
     * @return object|null
     */
    private static function readResolvedTenant(Container $container): ?object
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\SubjectResolver $resolver */
        $resolver = $container->make(SubjectResolver::class);

        /** @var \SineMacula\Laravel\Authorization\Support\ResolvedTenant $resolved */
        $resolved = $container->make(ResolvedTenant::class);

        if (!$resolved->isFrom($resolver)) {
            $resolved = $container->instance(ResolvedTenant::class, ResolvedTenant::from($resolver));
        }

        return $resolved->tenant;
    }
}
