<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Observers\Support;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * What the record observers read before a write, held until the write is made
 * and its event built: the changed fields' values before an update, and the
 * rows a delete takes with it.
 *
 * Values are reported as plain values: a scalar or null as it is, a date as an
 * ISO 8601 string in UTC, a backed enum as its value, and anything else as
 * null, so an event never carries an object.
 *
 * @managed-static
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordChanges
{
    /** @var \WeakMap<\Illuminate\Database\Eloquent\Model, array<string, scalar|null>>|null The changed fields' values before each pending update. */
    private static ?\WeakMap $before = null;

    /** @var \WeakMap<\Illuminate\Database\Eloquent\Model, array<string, mixed>>|null What each pending write read before it was made. */
    private static ?\WeakMap $held = null;

    /**
     * Capture the values the model's dirty fields held before the pending
     * update, leaving out the given fields.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  list<string>  $except
     * @return void
     */
    public static function capture(Model $model, array $except = []): void
    {
        $before = [];

        foreach (\array_keys($model->getDirty()) as $key) {
            if (\in_array($key, $except, true)) {
                continue;
            }

            $before[$key] = self::plain($model->getOriginal($key));
        }

        self::before()[$model] = $before;
    }

    /**
     * Return the captured fields' values before the update and after it, and
     * forget the capture.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return array{before: array<string, scalar|null>, after: array<string, scalar|null>}
     */
    public static function diff(Model $model): array
    {
        $captured = self::before();
        $before   = $captured[$model] ?? [];
        $after    = [];

        unset($captured[$model]);

        foreach (\array_keys($before) as $key) {
            $after[$key] = self::plain($model->getAttribute($key));
        }

        return ['before' => $before, 'after' => $after];
    }

    /**
     * Hold what was read before the model's pending write.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  array<string, mixed>  $values
     * @return void
     */
    public static function hold(Model $model, array $values): void
    {
        self::held()[$model] = $values;
    }

    /**
     * Return what was held for the model's write, and forget it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return array<string, mixed>
     */
    public static function release(Model $model): array
    {
        $held   = self::held();
        $values = $held[$model] ?? [];

        unset($held[$model]);

        return $values;
    }

    /**
     * Return a reference to every row a many-to-many relation links the model
     * to, read from the pivot table, so no scope hides a row.
     *
     * @param  \Illuminate\Database\Eloquent\Relations\BelongsToMany<covariant \Illuminate\Database\Eloquent\Model, *, *>  $relation
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    public static function linked(BelongsToMany $relation): array
    {
        $type = $relation->getRelated()->getMorphClass();
        $keys = $relation->newPivotQuery()->pluck($relation->getRelatedPivotKeyName())->all();

        return \array_values(\array_map(static fn (mixed $key): Reference => new Reference($type, \is_scalar($key) ? (string) $key : ''), $keys));
    }

    /**
     * Return a field's value as a plain value.
     *
     * @param  mixed  $value
     * @return scalar|null
     */
    private static function plain(mixed $value): bool|float|int|string|null
    {
        return match (true) {
            $value === null, \is_scalar($value)  => $value,
            $value instanceof \DateTimeInterface => CarbonImmutable::instance($value)->utc()->toIso8601String(),
            $value instanceof \BackedEnum        => $value->value,
            default                              => null,
        };
    }

    /**
     * Return the map of captured values, creating it on first access.
     *
     * @return \WeakMap<\Illuminate\Database\Eloquent\Model, array<string, scalar|null>>
     */
    private static function before(): \WeakMap
    {
        return self::$before ??= new \WeakMap;
    }

    /**
     * Return the map of held values, creating it on first access.
     *
     * @return \WeakMap<\Illuminate\Database\Eloquent\Model, array<string, mixed>>
     */
    private static function held(): \WeakMap
    {
        return self::$held ??= new \WeakMap;
    }
}
