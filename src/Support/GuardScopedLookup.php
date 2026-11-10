<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Database\ComposedExpression;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;

/**
 * Shared owner- and guard-precedence query builder.
 *
 * `RoleService::find()`, `PermissionService::find()` and the grant service's
 * name lookups need an identical query that finds a row by name under a guard.
 * A name is unique within its owner and guard, not globally, so several rows
 * can answer: the current tenant's, each of its ancestors' and the platform's,
 * each for the guard or guard-agnostic. This helper owns the single copy of the
 * precedence between them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GuardScopedLookup
{
    /**
     * Find a row by name under the given guard for the supplied model class.
     *
     * The model's global scopes apply, so the tenant scope limits the
     * candidates to the platform's rows and those of the current tenant and its
     * ancestors. Among them the nearest owner's row wins (the tenant's, then
     * each ancestor's in turn, then the platform's), then a row for the guard
     * wins over a guard-agnostic one, and the primary key breaks any remaining
     * tie, so the same row is found every time.
     *
     * The return is typed as `Model|null`; callers validate the concrete class
     * with `instanceof` before using the result. Larastan cannot flow a
     * `TModel` template through `new $class->newQuery()->first()` (the Builder
     * generic is inferred as `Model` once the receiver is a dynamic
     * class-string), so a generic return shape would produce false
     * `return.type` errors at callsites. The `staticMethod.dynamicCall`
     * suppressions cover Laravel's `@method static` annotations on
     * `Illuminate\Database\Eloquent\Builder`; the dispatch is runtime-dynamic
     * on a Builder instance, not static.
     *
     * A null guard means the configured default
     * (`authorization.defaults.guard`).
     *
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $class
     * @param  string  $name
     * @param  string|null  $guard
     * @return \Illuminate\Database\Eloquent\Model|null
     */
    public static function findForGuard(string $class, string $name, ?string $guard = null): ?Model
    {
        /** @var string $default */
        $default = config('authorization.defaults.guard', 'web');

        return self::queryForGuard($class, $name, $guard ?? $default)->first();
    }

    /**
     * Return every row that answers the name under the given guard, in the
     * order `findForGuard()` ranks them.
     *
     * A revocation or synchronisation by name works from these, since an
     * identity may hold the platform's row while the current tenant owns one of
     * the same name that `findForGuard()` would pick. Given a tenant, the rows
     * visible in that tenant are read in place of the current tenant's.
     *
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $class
     * @param  string  $name
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return list<\Illuminate\Database\Eloquent\Model>
     */
    public static function allForGuard(string $class, string $name, string $guard, ?Reference $tenant = null): array
    {
        /** @var list<\Illuminate\Database\Eloquent\Model> */
        return self::queryForGuard($class, $name, $guard, $tenant)->get()->all();
    }

    /**
     * Build the query for the rows that answer the name under the given guard,
     * ordered by precedence.
     *
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $class
     * @param  string  $name
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>
     */
    private static function queryForGuard(string $class, string $name, string $guard, ?Reference $tenant = null): Builder
    {
        $instance = new $class;
        $grammar  = $instance->getConnection()->getQueryGrammar();
        $column   = static fn (string $column): string => $instance->qualifyColumn($column);

        $chain = $tenant === null ? TenantScope::currentChain() : TenantChain::of($tenant, TenantChain::tree());
        $query = $instance->newQuery();

        if ($tenant !== null) {
            $chain->owners($query->withoutGlobalScope(TenantScope::class), $column('tenant_type'), $column('tenant_id'));
        }

        // @phpstan-ignore staticMethod.dynamicCall
        $query->where($column('name'), $name)
            ->where(static function (Builder $query) use ($column, $guard): void {
                // @phpstan-ignore staticMethod.dynamicCall
                $query->where($column('guard'), $guard)->orWhereNull($column('guard'));
            });

        return $chain->nearestFirst($query, $grammar->wrap($column('tenant_type')), $grammar->wrap($column('tenant_id')))
            ->orderBy(new ComposedExpression($grammar->wrap($column('guard')) . ' IS NULL'))
            ->orderBy($instance->getQualifiedKeyName());
    }
}
