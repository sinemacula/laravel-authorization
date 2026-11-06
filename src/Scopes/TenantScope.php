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
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * Global query scope for row-level multi-tenant filtering.
 *
 * When the subject the `SubjectResolver` returns has a tenant, this scope
 * restricts queries to rows that are either platform-wide (null tenant columns)
 * or owned by that tenant or one of its ancestors in the bound tenant tree.
 * When there is no subject, or the subject has no tenant, only platform-wide
 * rows remain visible: a missing tenant never makes every tenant's rows
 * visible.
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
        self::currentChain()->owners($builder, $model->getTable() . '.tenant_type', $model->getTable() . '.tenant_id');
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
        $tenant = self::whileResolving(static fn (ResolvedTenant $resolved): ?object => $resolved->tenant);

        return $tenant === null ? null : self::extractTenantPair($tenant);
    }

    /**
     * Return the application the subject is on, which limits the grants that
     * count to those for every application and those for it, or null for none,
     * when only grants for every application count.
     *
     * @return string|null
     */
    public static function currentApplication(): ?string
    {
        return self::whileResolving(static fn (ResolvedTenant $resolved): ?string => $resolved->application);
    }

    /**
     * Return the tenant the scope limits rows to and its ancestors, through the
     * bound tenant tree, or the platform's empty chain.
     *
     * @return \SineMacula\Laravel\Authorization\Support\TenantChain
     */
    public static function currentChain(): TenantChain
    {
        return self::whileResolving(static fn (ResolvedTenant $resolved): TenantChain => $resolved->chain(TenantChain::tree())) ?? new TenantChain;
    }

    /**
     * Read the current tenant's ancestors again through the bound tenant tree,
     * in place of the chain held for the request or job, and return the chain
     * read, or the platform's empty chain.
     *
     * The resolution cache reads the chain again once it has pinned its
     * versions, so a tree change made before the pin is never stored against
     * the new versions.
     *
     * @return \SineMacula\Laravel\Authorization\Support\TenantChain
     */
    public static function refreshChain(): TenantChain
    {
        return self::whileResolving(static fn (ResolvedTenant $resolved): TenantChain => $resolved->refreshChain(TenantChain::tree())) ?? new TenantChain;
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
     * Read from the tenant resolved for the current request or job, or return
     * null for a query run while the subject, or its tenant's ancestors, are
     * being resolved.
     *
     * Resolving the subject can itself query a scoped model: the shipped
     * resolver reads the signed-in user, and a user model that eager-loads its
     * roles and permissions queries them. Those queries, on any scoped model,
     * see platform rows only, so the resolver runs once rather than again for
     * each model, or without end. The same holds while the tenant tree reads a
     * tenant's ancestors.
     *
     * @template TValue
     *
     * @param  \Closure(\SineMacula\Laravel\Authorization\Support\ResolvedTenant): TValue  $read
     * @return TValue|null
     */
    private static function whileResolving(\Closure $read): mixed
    {
        $container = Container::getInstance();

        if ($container->bound(self::RESOLVING)) {
            return null;
        }

        $container->instance(self::RESOLVING, true);

        try {
            return $read(self::readResolvedTenant($container));
        } finally {
            $container->forgetInstance(self::RESOLVING);
        }
    }

    /**
     * Return the holder of the tenant resolved for the current request or job,
     * resolving it again when the bound resolver is not the one it was read
     * from.
     *
     * @param  \Illuminate\Container\Container  $container
     * @return \SineMacula\Laravel\Authorization\Support\ResolvedTenant
     */
    private static function readResolvedTenant(Container $container): ResolvedTenant
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\SubjectResolver $resolver */
        $resolver = $container->make(SubjectResolver::class);

        /** @var \SineMacula\Laravel\Authorization\Support\ResolvedTenant $resolved */
        $resolved = $container->make(ResolvedTenant::class);

        if (!$resolved->isFrom($resolver)) {
            $resolved = $container->instance(ResolvedTenant::class, ResolvedTenant::from($resolver));
        }

        return $resolved;
    }
}
