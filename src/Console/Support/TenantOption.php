<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * A console option naming a tenant as `{morphType}:{key}`, read the same way by
 * `authorization:why` and `authorization:review`.
 *
 * A type the morph map or a class name resolves to an Eloquent model names that
 * model's row, which must exist, by its morph class; any other type is the
 * tenant reference as given. Anything else is refused with
 * `InvalidArgumentException`, whose message names the option alone, never the
 * value given: a value not in the format, a row that does not exist, or a
 * lookup that fails, as one whose key the key column cannot hold does on some
 * databases, without naming the failure.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TenantOption
{
    /**
     * Return the reference to the tenant the option's value names.
     *
     * @param  string  $option
     * @param  mixed  $value
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     *
     * @throws \InvalidArgumentException
     */
    public static function reference(string $option, mixed $value): Reference
    {
        $parts = \explode(':', \is_string($value) ? $value : '', 2);

        if (\count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new \InvalidArgumentException("The --{$option} option must be in the format {morphType}:{key} (e.g. team:1).");
        }

        return self::tenant($option, $parts[0], $parts[1]);
    }

    /**
     * Return the reference to the tenant of the type and key: the row of the
     * Eloquent model the type resolves to, by its morph class, or the type and
     * key as given when it resolves to none.
     *
     * @param  string  $option
     * @param  string  $type
     * @param  string  $key
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function tenant(string $option, string $type, string $key): Reference
    {
        $class = Relation::getMorphedModel($type) ?? $type;

        if (!\is_subclass_of($class, Model::class)) {
            return new Reference($type, $key);
        }

        try {
            $model = $class::query()->find($key);
        } catch (\Throwable) { // @phpstan-ignore catch.neverThrown (the query may fail, as one with a key the key column cannot hold does on PostgreSQL)
            throw new \InvalidArgumentException("The --{$option} option could not be resolved.");
        }

        return Reference::of($model ?? throw new \InvalidArgumentException("The --{$option} option names no saved row."));
    }
}
