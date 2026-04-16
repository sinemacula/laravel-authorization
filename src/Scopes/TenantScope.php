<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Scopes;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Scope;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;

/**
 * Global query scope for row-level multi-tenant filtering.
 *
 * When a `TenantResolver` returns a non-null tenant, this scope
 * restricts queries to rows that are either global (null tenant
 * columns) or owned by the resolved tenant. When the resolver
 * returns null (no tenant context), no filtering is applied and
 * all rows remain visible — preserving backward-compatible
 * platform-level behaviour.
 *
 * The scope memoises the resolver result on the instance so a
 * single Eloquent request-pattern (the `effectivePermissions()`
 * enum sweep, relation walks, cache-miss paths) pays the
 * resolver cost once rather than once per query. Call
 * `flushResolvedTenant()` at the request boundary under Octane
 * to clear the memo.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Database\Eloquent\Scope<\Illuminate\Database\Eloquent\Model>
 */
class TenantScope implements Scope
{
    /**
     * Memoised tenant resolver result, keyed by the container
     * instance whose `TenantResolver` binding produced it.
     *
     * Eloquent invokes `apply()` for every query against the
     * scoped model, so calling the resolver on every invocation is
     * wasteful when the resolver does non-trivial work (DB lookup,
     * JWT decode, cache miss). Keying the memo by
     * `spl_object_id(container)` means long-lived processes
     * (Octane / RoadRunner / Swoole) that rebuild the container
     * between requests automatically invalidate the memo — the
     * next `apply()` observes a new container hash and re-resolves.
     * The old entry is replaced, not accumulated, so the memo
     * never holds more than one live request's tenant.
     *
     * @var array{container_id: int, tenant: object|null}|null
     */
    private ?array $resolvedTenantMemo = null;

    /**
     * Apply the tenant scope to the given Eloquent builder.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  \Illuminate\Database\Eloquent\Builder<*>  $builder
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    public function apply(Builder $builder, Model $model): void
    {
        $tenant = $this->resolveTenant();

        if ($tenant === null) {
            return;
        }

        [$morphType, $morphId] = self::extractTenantPair($tenant);

        // `whereNull` / `orWhere` are declared as `@method static`
        // on the Eloquent Builder docblock; PHPStan flags dynamic
        // instance calls as `staticMethod.dynamicCall` even though
        // runtime dispatch is genuinely dynamic. The same pattern
        // is used in `GuardScopedLookup` — docblock-soup artefacts,
        // not unsafe calls.
        // @phpstan-ignore staticMethod.dynamicCall
        $builder->where(function ($q) use ($model, $morphType, $morphId): void {
            // @phpstan-ignore staticMethod.dynamicCall
            $q->whereNull($model->getTable() . '.tenant_type')
                ->orWhere(function ($q2) use ($model, $morphType, $morphId): void {
                    $q2->where($model->getTable() . '.tenant_type', $morphType)
                        ->where($model->getTable() . '.tenant_id', $morphId);
                });
        });
    }

    /**
     * Extract the `(tenant_type, tenant_id)` pair from an arbitrary
     * tenant object, refusing anything that cannot supply a stable
     * pair without a `spl_object_hash`-style fallback.
     *
     * Shared by the global scope and the `scopeForTenant` local
     * scope on `Role` / `Permission` so the acceptance rules have a
     * single owner.
     *
     * @param  object  $tenant
     * @return array{0: string, 1: string}
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    public static function extractTenantPair(object $tenant): array
    {
        if ($tenant instanceof Model || $tenant instanceof AuthorizableTenant) {
            /** @var int|string|null $key */
            $key = $tenant->getKey();

            return [$tenant->getMorphClass(), (string) $key];
        }

        throw new InvalidTenantException($tenant);
    }

    /**
     * Flush the memoised tenant resolver result. Exposed for tests
     * and for consumers that pivot the current tenant mid-request
     * (for example an admin console that switches context).
     *
     * @return void
     */
    public function flushResolvedTenant(): void
    {
        $this->resolvedTenantMemo = null;
    }

    /**
     * Resolve the current tenant, memoising the result for the
     * lifetime of the current container instance. Long-lived
     * processes that rebuild the container per request (Octane)
     * observe a new container ID on the next call and re-resolve.
     *
     * @return object|null
     */
    private function resolveTenant(): ?object
    {
        $container   = \Illuminate\Container\Container::getInstance();
        $containerId = \spl_object_id($container);

        if ($this->resolvedTenantMemo !== null && $this->resolvedTenantMemo['container_id'] === $containerId) {
            return $this->resolvedTenantMemo['tenant'];
        }

        /** @var \SineMacula\Laravel\Authorization\Contracts\TenantResolver $resolver */
        $resolver = $container->make(TenantResolver::class);
        $tenant   = $resolver->resolve();

        $this->resolvedTenantMemo = [
            'container_id' => $containerId,
            'tenant'       => $tenant,
        ];

        return $tenant;
    }
}
