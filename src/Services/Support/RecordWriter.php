<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;

/**
 * Saves and deletes role, permission and policy rows for the record services,
 * each in one transaction on the package's connection that covers looking the
 * row up as well as writing it.
 *
 * The write goes through the model, so its observer, name validation and system
 * protection run as they do for any save.
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
     * @param  \Closure(): TModel  $model
     * @param  array<string, mixed>  $attributes
     * @return TModel
     *
     * @throws \Throwable
     */
    public static function save(\Closure $model, array $attributes): Model
    {
        return AuthorizationConnection::connection()->transaction(static function () use ($model, $attributes): Model {
            $record = $model();

            $record->forceFill($attributes)->save();

            return $record;
        });
    }

    /**
     * Delete the model the callback returns.
     *
     * @param  \Closure(): \Illuminate\Database\Eloquent\Model  $model
     * @return void
     *
     * @throws \Throwable
     */
    public static function delete(\Closure $model): void
    {
        AuthorizationConnection::connection()->transaction(static function () use ($model): void {
            $model()->delete();
        });
    }
}
