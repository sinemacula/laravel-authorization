<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Scopes;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Scope;
use SineMacula\Laravel\Authorization\Contracts\TenantResolver;

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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Database\Eloquent\Scope<\Illuminate\Database\Eloquent\Model>
 */
class TenantScope implements Scope
{
    /**
     * Apply the tenant scope to the given Eloquent builder.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  \Illuminate\Database\Eloquent\Builder<*>  $builder
     * @return void
     */
    public function apply(Builder $builder, Model $model): void
    {
        $tenant = app(TenantResolver::class)->resolve();

        if ($tenant === null) {
            return;
        }

        $morphType = $tenant instanceof Model
            ? $tenant->getMorphClass()
            : $tenant::class;

        $morphId = method_exists($tenant, 'getKey')
            ? (string) $tenant->getKey()
            : spl_object_hash($tenant);

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
}
