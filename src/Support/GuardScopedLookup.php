<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * Shared guard-precedence query builder.
 *
 * Both `Role::resolveByName()` and `Permission::resolveByName()`
 * need an identical query that finds a row by `(name, guard)` with
 * guard-specific rows outranking guard-agnostic rows. This helper
 * owns the single copy of that logic so the two models delegate here
 * instead of carrying duplicated private methods.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GuardScopedLookup
{
    /**
     * Find a row by `(name, guard)` for the supplied model class,
     * preferring guard-specific rows over guard-agnostic ones. The
     * lookup is the shared half of `Role::resolveByName()` /
     * `Permission::resolveByName()`. The return is typed as
     * `Model|null`; callers validate the concrete class with
     * `instanceof` before using the result. Larastan cannot flow a
     * `TModel` template through
     * `new $class->newQuery()->first()` (the Builder generic is
     * inferred as `Model` once the receiver is a dynamic
     * class-string), so a generic return shape would produce false
     * `return.type` errors at callsites. The two
     * `staticMethod.dynamicCall` suppressions on `orderByRaw()` and
     * `orWhereNull()` cover Laravel's `@method static` annotations
     * on `Illuminate\Database\Eloquent\Builder`; the dispatch is
     * runtime-dynamic on a Builder instance, not static.
     *
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $class
     * @param  string  $name
     * @param  string  $guard
     * @return \Illuminate\Database\Eloquent\Model|null
     */
    public static function findForGuard(string $class, string $name, string $guard): ?Model
    {
        $instance = new $class;

        // @phpstan-ignore staticMethod.dynamicCall
        return $instance->newQuery()
            ->where('name', $name)
            ->where(static function (Builder $query) use ($guard): void {
                // @phpstan-ignore staticMethod.dynamicCall
                $query->where('guard', $guard)->orWhereNull('guard');
            })
            ->orderByRaw('guard IS NULL')
            ->first();
    }
}
