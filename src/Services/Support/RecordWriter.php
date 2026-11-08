<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Exceptions\UnsavedRecordException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;

/**
 * Saves and deletes role, permission and policy rows for the record services,
 * each in one transaction on the package's connection that covers looking the
 * row up as well as writing it.
 *
 * The write goes through the model, so its observer, name validation and system
 * protection run as they do for any save, as one operation for the given acting
 * context, or trusted with none: every event the write dispatches carries the
 * operation, once the write commits. With an acting context, the change is
 * decided, as the definition's operation resource under the action, inside the
 * transaction once the row is looked up and read again as stored, and before it
 * is written, a policy given a document on the resource
 * `OperationResource::rewrite()` builds, so the change can be compared with the
 * stored one exactly as a screen compares it, and a refusal throws with nothing
 * written. A new record is owned by the tenant it is given (see `ownedBy()`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordWriter
{
    /** @var array<string, string> The attributes a change to a definition is offered under, by column. */
    private const array CHANGES = [
        'name'        => 'name',
        'description' => 'description',
        'rank'        => 'rank',
        'guard'       => 'guard',
        'category'    => 'category',
        'parent_id'   => 'parent',
        'owner_type'  => 'owner_type',
        'owner_id'    => 'owner_id',
    ];

    /**
     * Set the given attributes on the model the callback returns, and save it,
     * once the acting context, when there is one, is allowed the action on it.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  string  $action
     * @param  \Closure(): TModel  $model
     * @param  array<string, mixed>  $attributes
     * @return TModel
     *
     * @throws \Throwable
     */
    public static function save(?ActingContext $actor, string $action, \Closure $model, array $attributes): Model
    {
        return OperationScope::run(Operation::begin($actor, [$action]), static function (Operation $operation) use ($actor, $action, $model, $attributes): Model {
            $record = self::stored($model(), $actor);

            $actor?->authorizeIn($operation, self::resourceOf($action, $record, $attributes));

            $record->forceFill($attributes)->save();

            return $record;
        });
    }

    /**
     * Create the record of the model given, keyed by the id, or a new key when
     * none is given, with the given attributes, once the acting context, when
     * there is one, is allowed the action on it, as `save()` saves it.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  string  $action
     * @param  TModel  $model
     * @param  string|null  $id
     * @param  array<string, mixed>  $attributes
     * @return TModel
     *
     * @throws \Throwable
     */
    public static function create(?ActingContext $actor, string $action, Model $model, ?string $id, array $attributes): Model
    {
        return self::save($actor, $action, static fn (): Model => $model, [$model->getKeyName() => $id, ...$attributes]);
    }

    /**
     * Return the new model owned by the tenant given, its tenant columns set to
     * the tenant's morph type and key, so its creation is decided in that
     * tenant, and by the owner rule against it (D20); with none, the model as
     * it is, owned by the platform.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  TModel  $model
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant|null  $tenant
     * @return TModel
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    public static function ownedBy(Model $model, AuthorizableTenant|Model|null $tenant): Model
    {
        if ($tenant === null) {
            return $model;
        }

        [$type, $id] = TenantScope::extractTenantPair($tenant);

        return $model->forceFill(['tenant_type' => $type, 'tenant_id' => $id]);
    }

    /**
     * Delete the model the callback returns, once the acting context, when
     * there is one, is allowed the action on it.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  string  $action
     * @param  \Closure(): \Illuminate\Database\Eloquent\Model  $model
     * @return void
     *
     * @throws \Throwable
     */
    public static function delete(?ActingContext $actor, string $action, \Closure $model): void
    {
        OperationScope::run(Operation::begin($actor, [$action]), static function (Operation $operation) use ($actor, $action, $model): void {
            $record = self::stored($model(), $actor);

            $actor?->authorizeIn($operation, OperationResource::definition($action, $record));

            $record->delete();
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

    /**
     * Return the record a change is weighed on and writes: for a delegated
     * change to a saved record, the record read again as stored, discarding
     * changes to it not saved, so a change is never judged on a rank, a parent
     * or a document the row does not hold, and never writes one it did not
     * weigh; the record as given otherwise.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  TModel  $record
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return TModel
     */
    private static function stored(Model $record, ?ActingContext $actor): Model
    {
        return $actor === null || !$record->exists ? $record : $record->refresh();
    }

    /**
     * Return the operation resource the change is decided on: for a policy
     * given a document, the one `OperationResource::rewrite()` builds, as a
     * screen would build it, so the document is weighed, and offered by digest,
     * as it would be stored; for any other change, the definition's.
     *
     * @param  string  $action
     * @param  \Illuminate\Database\Eloquent\Model  $record
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Authorization\Administration\OperationResource
     */
    private static function resourceOf(string $action, Model $record, array $attributes): OperationResource
    {
        $change = self::changeOf($attributes);

        return \array_key_exists('document', $attributes)
            ? OperationResource::rewrite($record, $attributes['document'], $change, $action)
            : OperationResource::definition($action, $record, $change);
    }

    /**
     * Return the proposed change the attributes make, as the operation resource
     * offers it: each scalar or null attribute under its name.
     *
     * @param  array<string, mixed>  $attributes
     * @return array<string, bool|float|int|string|null>
     */
    private static function changeOf(array $attributes): array
    {
        $change = [];

        foreach (self::CHANGES as $column => $name) {
            $value = $attributes[$column] ?? null;

            if (!\is_scalar($value)) {
                continue;
            }

            $change[$name] = $value;
        }

        return $change;
    }
}
