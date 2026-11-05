<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Database;

use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Stores an instant in UTC and reads it back as a UTC `Carbon`.
 *
 * A `dateTime` column keeps a wall-clock time with no zone, and Eloquent's own
 * `datetime` cast writes a date in whatever zone it carries and reads the
 * column back in the application's zone. An expiry given in another zone would
 * then be stored as that zone's wall-clock time and lapse early or late by the
 * offset. This cast converts every instant to UTC before it is written and
 * reads the column as UTC, so the stored value means the same instant whatever
 * zone the caller or the application uses. A string without an offset is taken
 * to be UTC already.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Database\Eloquent\CastsAttributes<\Illuminate\Support\Carbon|null, \DateTimeInterface|string|null>
 */
final class UtcDateTime implements CastsAttributes
{
    /**
     * Read the stored UTC wall-clock time as a UTC instant.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $key
     * @param  mixed  $value
     * @param  array<string, mixed>  $attributes
     * @return \Illuminate\Support\Carbon|null
     */
    #[\Override]
    public function get(Model $model, string $key, mixed $value, array $attributes): ?Carbon
    {
        return self::toUtc($value);
    }

    /**
     * Convert the instant to UTC and format it for the column.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $key
     * @param  mixed  $value
     * @param  array<string, mixed>  $attributes
     * @return string|null
     */
    #[\Override]
    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        return self::toUtc($value)?->format($model->getDateFormat());
    }

    /**
     * Return the given instant in UTC, or null when there is none.
     *
     * A date keeps the instant it names; a string without an offset is read as
     * UTC wall-clock time, as the column stores it.
     *
     * @param  mixed  $value
     * @return \Illuminate\Support\Carbon|null
     */
    public static function toUtc(mixed $value): ?Carbon
    {
        return match (true) {
            $value instanceof \DateTimeInterface => Carbon::instance($value)->utc(),
            \is_string($value) && $value !== ''  => Carbon::parse($value, 'UTC')->utc(),
            default                              => null,
        };
    }
}
