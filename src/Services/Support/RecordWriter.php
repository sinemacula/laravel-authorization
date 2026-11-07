<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Exceptions\UnsavedRecordException;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;

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
 * transaction once the row is looked up and before it is written, with the
 * document a policy is given as it would be stored, so the change can be
 * compared with the stored one, and a refusal throws with nothing written.
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
            $record = $model();

            $document = self::documentOf($record, $attributes);

            $actor?->authorizeIn($operation, OperationResource::definition($action, $record, self::changeOf($attributes, $document), $document));

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
            $record = $model();

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
     * Return the proposed change the attributes make, as the operation resource
     * offers it: each scalar or null attribute under its name, and a policy
     * document by the digest of the document as it would be stored, the one the
     * policy events report and a grantable right names, none for one that
     * cannot be read.
     *
     * @param  array<string, mixed>  $attributes
     * @param  array<string, mixed>|null  $document
     * @return array<string, bool|float|int|string|null>
     */
    private static function changeOf(array $attributes, ?array $document = null): array
    {
        $change = [];

        foreach (self::CHANGES as $column => $name) {
            $value = $attributes[$column] ?? null;

            if (!\is_scalar($value)) {
                continue;
            }

            $change[$name] = $value;
        }

        if (\array_key_exists('document', $attributes)) {
            $change['digest'] = self::digestOf($document);
        }

        return $change;
    }

    /**
     * Return the document the attributes give a policy, as it would be stored,
     * named as the policy is, or null when they give none, or one that cannot
     * be read, which the save then refuses as it refuses any.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $record
     * @param  array<string, mixed>  $attributes
     * @return array<string, mixed>|null
     */
    private static function documentOf(Model $record, array $attributes): ?array
    {
        if (!\array_key_exists('document', $attributes)) {
            return null;
        }

        try {
            return PolicyDocument::named(PolicyDocument::decode($attributes['document'], ''), $attributes['name'] ?? $record->getAttribute('name'));
        } catch (InvalidPolicyDocumentException) {
            return null;
        }
    }

    /**
     * Return the digest of a proposed policy document, as it would be stored,
     * or null for one that cannot be read, which the save then refuses as it
     * refuses any.
     *
     * @param  array<string, mixed>|null  $document
     * @return string|null
     */
    private static function digestOf(?array $document): ?string
    {
        try {
            return $document === null ? null : DocumentDigest::of($document)->digest;
        } catch (\JsonException) {
            return null;
        }
    }
}
