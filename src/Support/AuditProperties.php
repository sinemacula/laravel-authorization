<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;

/**
 * The details a change event reports to an audit mapper, as
 * `AuthorizationMutation::auditProperties()` returns them: every property of
 * the event, flat and serialisable.
 *
 * Each key is the property's name in snake case; a scope, a document digest or
 * a map of changes is flattened under a dotted key (`scope.include_subtree`,
 * `document.digest`, `changes.before.name`). A reference is written as
 * `type:id`, a date as an ISO 8601 string in UTC and a backed enum as its
 * value. The operation is left out, since it carries the call and its client,
 * and so are the grantee, the grantees, the tenant and the scope's tenant and
 * application, which the other accessors return. Any object besides these, a
 * model or a closure included, is refused, so a mapper never stores one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuditProperties
{
    /** @var list<string> The keys left out, carried by the operation or by the other accessors. */
    private const array OMITTED = ['operation', 'grantee', 'grantees', 'tenant', 'scope.tenant', 'scope.application'];

    /**
     * Return the event's details, flat and serialisable.
     *
     * @param  object  $event
     * @return array<string, list<scalar>|scalar|null>
     *
     * @throws \LogicException
     */
    public static function of(object $event): array
    {
        return self::flatten('', \get_object_vars($event));
    }

    /**
     * Return the values under the prefix, each keyed in snake case, without the
     * keys left out.
     *
     * @param  string  $prefix
     * @param  array<array-key, mixed>  $values
     * @return array<string, list<scalar>|scalar|null>
     *
     * @throws \LogicException
     */
    private static function flatten(string $prefix, array $values): array
    {
        $properties = [];

        foreach ($values as $name => $value) {
            $key = $prefix . Str::snake((string) $name);

            if (\in_array($key, self::OMITTED, true)) {
                continue;
            }

            $properties = [...$properties, ...self::entry($key, $value)];
        }

        return $properties;
    }

    /**
     * Return the entries one value contributes: a map or a nested value object
     * flattened under its key, else the value itself, a list of values kept as
     * a list.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return array<string, list<scalar>|scalar|null>
     *
     * @throws \LogicException
     */
    private static function entry(string $key, mixed $value): array
    {
        if (\is_array($value)) {
            return \array_is_list($value) ? [$key => \array_map(self::scalar(...), $value)] : self::flatten($key . '.', $value);
        }

        if ($value instanceof GrantScope || $value instanceof DocumentDigest) {
            return self::flatten($key . '.', \get_object_vars($value));
        }

        return [$key => $value === null ? null : self::scalar($value)];
    }

    /**
     * Return the value as a scalar: a reference as `type:id`, a date as an ISO
     * 8601 string in UTC, a backed enum as its value.
     *
     * @param  mixed  $value
     * @return scalar
     *
     * @throws \LogicException
     */
    private static function scalar(mixed $value): bool|float|int|string
    {
        return match (true) {
            \is_scalar($value)                   => $value,
            $value instanceof Reference          => $value->type . ':' . $value->id,
            $value instanceof \DateTimeInterface => CarbonImmutable::instance($value)->utc()->toIso8601String(),
            $value instanceof \BackedEnum        => $value->value,
            default                              => throw new \LogicException('An event detail is not a plain value: ' . \get_debug_type($value) . '.'),
        };
    }
}
