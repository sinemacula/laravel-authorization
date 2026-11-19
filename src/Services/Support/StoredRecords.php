<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Exceptions\UnwrittenGrantException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The role, permission or policy a delegated change hands out, as stored, so
 * the change is weighed on the row it writes against, never on the model in
 * hand: a model with unsaved changes, or one read before another write changed
 * its row, would otherwise be judged on a rank, a name or a document the row
 * does not hold, while the grant is written against the row's key.
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

    /**
     * Give the model a caller handed a delegated change the state of the record
     * the change wrote, a fresh instance read or copied for the try that
     * committed, and return it: its attributes, as the original, and whether it
     * exists, so the caller's model reads as it would had the change been
     * written on it. A model that is the record already is returned as it is.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  TModel  $given
     * @param  \Illuminate\Database\Eloquent\Model  $record
     * @return TModel
     */
    public static function adopt(Model $given, Model $record): Model
    {
        if ($given === $record) {
            return $given;
        }

        $given->setRawAttributes($record->getAttributes(), true);

        $given->exists             = $record->exists;
        $given->wasRecentlyCreated = $record->wasRecentlyCreated;

        return $given;
    }

    /**
     * Return the change a grant of the target to the grantee wrote, and refuse
     * one that wrote no row (null): as the target's when its row is gone, else
     * as the role's when the grantee is a role whose row is gone, else as not
     * written.
     *
     * @param  \SineMacula\Laravel\Authorization\Services\Support\GrantChange|null  $change
     * @param  string  $kind
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantChange
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnwrittenGrantException
     */
    public static function written(?GrantChange $change, string $kind, Model $target, Model|Reference $grantee): GrantChange
    {
        if ($change !== null) {
            return $change;
        }

        if (self::isGone($target)) {
            throw new InvalidGrantTargetException($kind, $target);
        }

        if ($grantee instanceof Role && self::isGone($grantee)) {
            throw new InvalidGrantTargetException('role', $grantee);
        }

        $name      = $target->getAttribute('name');
        $reference = Reference::of($grantee);

        throw new UnwrittenGrantException("grant of {$kind} '" . (\is_scalar($name) ? (string) $name : '') . "' to {$reference->type}:{$reference->id}");
    }

    /**
     * Determine whether the model's row is gone, by a locking read on the write
     * connection outside every global scope, so a delete committed since the
     * transaction began is seen.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return bool
     */
    private static function isGone(Model $model): bool
    {
        return $model->newQueryWithoutScopes()->useWritePdo()->whereKey($model->getKey())->sharedLock()->doesntExist();
    }
}
