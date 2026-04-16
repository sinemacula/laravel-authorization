<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * Shared guard-precedence query builder.
 *
 * Both `Role::resolveByName()` and `Permission::resolveByName()`
 * need an identical query that finds a row by `(name, guard_name)`
 * with guard-specific rows outranking guard-agnostic rows. This
 * helper owns the single copy of that logic so the two models
 * delegate here instead of carrying duplicated private methods.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GuardScopedLookup
{
    /**
     * Build the guard-precedence query for the supplied model class
     * and name. Returns rows matching the exact name where the
     * `guard_name` equals the supplied guard or is null (agnostic),
     * ordered so guard-specific rows sort first.
     *
     * The configured model is instantiated through `new $class` so
     * PHPStan resolves the receiver as an Eloquent `Model` instance
     * — `newQuery()`, `where()`, and the closure receiver type
     * cleanly without ignores. The remaining two suppressions on
     * `orderByRaw()` and `orWhereNull()` exist because Laravel
     * declares those methods via `@method static` annotations on
     * `Illuminate\Database\Eloquent\Builder`, which PHPStan flags
     * as `staticMethod.dynamicCall` whenever they appear inside an
     * instance-method chain. They are runtime-dynamic instance
     * calls; the static-receiver shape is a docblock artefact of
     * Laravel's annotation soup, not the actual call dispatch.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  class-string<TModel>  $class
     * @param  string  $name
     * @param  string  $guard
     * @return \Illuminate\Database\Eloquent\Builder<TModel>
     */
    public static function queryForGuard(string $class, string $name, string $guard): Builder
    {
        /** @var TModel $instance */
        $instance = new $class;

        // The chain ends in `orderByRaw()`, which Laravel declares
        // as `@method static` on Illuminate\Database\Eloquent\Builder.
        // PHPStan flags any dynamic call to such a method as
        // `staticMethod.dynamicCall` even though runtime dispatch is
        // genuinely dynamic instance dispatch on a Builder instance.
        // The same applies to `orWhereNull()` inside the closure
        // below. Both ignores are docblock-soup artefacts, not
        // unsafe calls.
        // @phpstan-ignore staticMethod.dynamicCall
        return $instance->newQuery()
            ->where('name', $name)
            ->where(static function (Builder $query) use ($guard): void {
                // @phpstan-ignore staticMethod.dynamicCall
                $query->where('guard_name', $guard)->orWhereNull('guard_name');
            })
            ->orderByRaw('guard_name IS NULL');
    }
}
