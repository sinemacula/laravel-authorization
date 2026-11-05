<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Exceptions\UnsavedRecordException;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Saves and deletes role, permission and policy rows for the record services,
 * each in one transaction on the package's connection that covers looking the
 * row up as well as writing it.
 *
 * The write goes through the model, so its observer, name validation and system
 * protection run as they do for any save, as one operation for the given actor:
 * every event the write dispatches carries the actor and the operation's id,
 * once the write commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordWriter
{
    /**
     * Set the given attributes on the model the callback returns, and save it.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \Closure(): TModel  $model
     * @param  array<string, mixed>  $attributes
     * @return TModel
     *
     * @throws \Throwable
     */
    public static function save(Model|Reference|null $actor, \Closure $model, array $attributes): Model
    {
        return OperationScope::run(Operation::begin($actor), static function () use ($model, $attributes): Model {
            $record = $model();

            $record->forceFill($attributes)->save();

            return $record;
        });
    }

    /**
     * Delete the model the callback returns.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \Closure(): \Illuminate\Database\Eloquent\Model  $model
     * @return void
     *
     * @throws \Throwable
     */
    public static function delete(Model|Reference|null $actor, \Closure $model): void
    {
        OperationScope::run(Operation::begin($actor), static function () use ($model): void {
            $model()->delete();
        });
    }

    /**
     * Return the model once it is known to be saved, so a change to it never
     * creates a record outside `create()`, and refuse an unsaved one.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  string  $kind
     * @param  TModel  $model
     * @return TModel
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnsavedRecordException
     */
    public static function existing(string $kind, Model $model): Model
    {
        if (!$model->exists) {
            throw new UnsavedRecordException($kind, $model);
        }

        return $model;
    }
}
