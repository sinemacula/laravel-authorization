<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;

/**
 * The role, permission or policy a delegated change hands out, as stored, so
 * the change is weighed on the row it writes against, never on the model in
 * hand (AUTHZ-11.1): a model with unsaved changes, or one read before another
 * write changed its row, would otherwise be judged on a rank, a name or a
 * document the row does not hold, while the grant is written against the row's
 * key.
 *
 * The row is read by its key, on the write connection, outside every global
 * scope, inside the change's transaction, so it is the row as last committed
 * the write sees.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StoredRecords
{
    /**
     * Return the row of the model as stored, a new instance of its class,
     * refusing one whose row is gone with `InvalidGrantTargetException`.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  string  $kind
     * @param  TModel  $model
     * @return TModel
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     */
    public static function of(string $kind, Model $model): Model
    {
        $stored = $model->newQueryWithoutScopes()->useWritePdo()->find($model->getKey());

        return $stored instanceof $model ? $stored : throw new InvalidGrantTargetException($kind, $model);
    }
}
