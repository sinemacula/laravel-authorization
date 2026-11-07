<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;

/**
 * Compiles which records a resource pattern names (`KeyTarget`) into the
 * condition a row's key meets (C4, C9), each proved to hold exactly when the
 * text PHP reads from the key, `(string) getKey()`, is what `fnmatch()` would
 * match.
 *
 * - An integer key equals a value only when the value is an integer's canonical
 *   decimal text, `0` or an optional `-` and digits without a leading zero (so
 *   `-0`, `+1`, `01` and `1.0` name no record), within 64 bits; the digits are
 *   inlined as they are. A canonical value beyond 64 bits is refused, since a
 *   key column of the kind could not tell it apart.
 * - A uuid key equals a value only when it is a uuid's canonical lower-case
 *   text, the form PHP reads.
 * - A string key equals a value byte for byte, with the plain comparison an
 *   index can serve first.
 * - A key starts with a value when the bytes of its text do, the key exactly
 *   the value left out when the target says so.
 *
 * A key is compared only where the column proves that what the database holds
 * is what PHP reads: an integer key that may hold a real number or a value
 * beyond PHP's integers is refused (`column_type`), and so is a string key
 * whose collation is not exact (`column_collation`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KeyConditions
{
    /** @var string An integer's canonical decimal text, as PHP's `(string)` writes it. */
    private const string CANONICAL_INTEGER = '/\A(?:0|-?[1-9][0-9]*)\z/';

    /** @var string A uuid's canonical lower-case text, as PHP reads it from PostgreSQL. */
    private const string CANONICAL_UUID = '/\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z/';

    /**
     * Return the condition a row's key meets when the target names its record,
     * and why the comparison is refused, or null when it is not.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  \SineMacula\Laravel\Authorization\Query\KeyTarget  $target
     * @return array{string, \SineMacula\Laravel\Authorization\Query\Enums\RefusalReason|null}
     */
    public static function of(ResourceShape $shape, KeyTarget $target): array
    {
        $constant = match (true) {
            $target->isAll()  => QueryAuthorizer::EVERY_ROW,
            $target->isNone() => QueryAuthorizer::NO_ROW,
            default           => null,
        };

        $refusal = $constant === null ? self::refusalOf($shape) : null;

        if ($constant !== null || $refusal !== null) {
            return [$constant ?? QueryAuthorizer::NO_ROW, $refusal];
        }

        return $target->kind === KeyTarget::EQUALS ? self::equals($shape, $target->value) : [self::startsWith($shape, $target), null];
    }

    /**
     * Return the condition a row's key meets when it is the value, and why the
     * comparison is refused, or null when it is not.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  string  $value
     * @return array{string, \SineMacula\Laravel\Authorization\Query\Enums\RefusalReason|null}
     */
    public static function equals(ResourceShape $shape, string $value): array
    {
        $dialect = $shape->dialect;

        return match ($shape->keyKind) {
            ColumnKind::INTEGER => self::equalsInteger($shape->key, $value),
            ColumnKind::UUID    => [\preg_match(self::CANONICAL_UUID, $value) === 1 ? "{$shape->key} = '{$value}'" : QueryAuthorizer::NO_ROW, null],
            ColumnKind::STRING  => [Conditions::all([$dialect->equalsIndexed($shape->key, ColumnKind::STRING, $value), $dialect->equalsBytes($shape->key, $value)]), null],
        };
    }

    /**
     * Return the condition a row's integer key meets when it is the value: its
     * digits when the value is an integer's canonical text within 64 bits, no
     * row's for any other value, refused beyond 64 bits.
     *
     * @param  string  $key
     * @param  string  $value
     * @return array{string, \SineMacula\Laravel\Authorization\Query\Enums\RefusalReason|null}
     */
    private static function equalsInteger(string $key, string $value): array
    {
        if (\preg_match(self::CANONICAL_INTEGER, $value) !== 1) {
            return [QueryAuthorizer::NO_ROW, null];
        }

        // An integer's text within 64 bits reads back as itself; the least is
        // written as a sum, since its digits alone are beyond 64 bits.
        if ((string) (int) $value !== $value) {
            return [QueryAuthorizer::NO_ROW, RefusalReason::RESOURCE_PATTERN];
        }

        $literal = $value === (string) \PHP_INT_MIN ? '(' . (\PHP_INT_MIN + 1) . ' - 1)' : $value;

        return ["{$key} = {$literal}", null];
    }

    /**
     * Return the condition a row's key meets when its text starts with the
     * target's value, the key exactly the value left out when asked.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  \SineMacula\Laravel\Authorization\Query\KeyTarget  $target
     * @return string
     */
    private static function startsWith(ResourceShape $shape, KeyTarget $target): string
    {
        $starts = $shape->dialect->startsWith($shape->key, $target->value);

        return $target->isValueExcluded ? Conditions::all([$starts, Conditions::not($shape->dialect->equalsBytes($shape->key, $target->value))]) : $starts;
    }

    /**
     * Return why the shape's key cannot be compared with a value, or null when
     * it can.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @return \SineMacula\Laravel\Authorization\Query\Enums\RefusalReason|null
     */
    private static function refusalOf(ResourceShape $shape): ?RefusalReason
    {
        return $shape->keyRefusal ?? ($shape->isKeyCollationExact ? null : RefusalReason::COLUMN_COLLATION);
    }
}
