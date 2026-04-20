<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Scopes;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Scope;

/**
 * Global query scope that hides deprecated permissions.
 *
 * Sync retires a permission row by stamping `deprecated_at` rather than
 * deleting it — role pivots stay intact, audit history survives. Gate
 * evaluation and the default API surface must never honour a deprecated
 * permission, so the scope restricts every query to `deprecated_at IS NULL`.
 * Admin flows that need to surface the full catalogue call `withDeprecated()`
 * on the model to disable the scope per-query.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Database\Eloquent\Scope<\Illuminate\Database\Eloquent\Model>
 */
class ExcludesDeprecatedScope implements Scope
{
    /**
     * Apply the scope to the given Eloquent builder.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>  $builder
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return void
     */
    #[\Override]
    public function apply(Builder $builder, Model $model): void
    {
        // @phpstan-ignore staticMethod.dynamicCall
        $builder->whereNull($model->getTable() . '.deprecated_at');
    }
}
