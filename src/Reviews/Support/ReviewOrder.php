<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;

/**
 * The one order an access review lists its rows in, the same on SQLite,
 * PostgreSQL and MySQL: a total order over the source kind (in the order
 * `Enums\SourceKind` declares them), the target, the grantee, the origin scope
 * and the route.
 *
 * Every string is compared byte for byte, as PHP's `strcmp()` compares it, so
 * neither a database's collation nor its locale moves a row: SQLite compares
 * with its binary collation, PostgreSQL through the `C` collation, and MySQL as
 * binary strings. Each nullable component is tagged first, a null before any
 * value, so the platform comes before every tenant and every application before
 * a named one, whatever a database does with nulls. A boolean orders false
 * before true.
 *
 * A key is built the same way from its parts: each part its length in bytes and
 * its bytes, a null as `~`, so no two lists of parts share a key, whatever
 * bytes they hold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReviewOrder
{
    /**
     * Order the query by the column, a null first when it may hold one, then
     * byte for byte.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $column
     * @param  bool  $isNullable
     * @return \Illuminate\Database\Query\Builder
     */
    public static function by(Builder $query, string $column, bool $isNullable = false): Builder
    {
        $wrapped = $query->getGrammar()->wrap($column);

        if ($isNullable) {
            $query->orderByRaw("case when {$wrapped} is null then 0 else 1 end");
        }

        $connection = $query->getConnection();

        return $query->orderByRaw(self::bytes($connection instanceof Connection ? $connection->getDriverName() : '', $wrapped));
    }

    /**
     * Compare two sort keys part by part: integers and booleans by value, a
     * null before any value, and strings byte for byte; a shorter key that is a
     * prefix of the other first.
     *
     * @param  list<bool|int|string|null>  $one
     * @param  list<bool|int|string|null>  $other
     * @return int
     */
    public static function compare(array $one, array $other): int
    {
        foreach ($one as $index => $part) {
            $order = \array_key_exists($index, $other) ? self::comparePart($part, $other[$index]) : 1;

            if ($order !== 0) {
                return $order;
            }
        }

        return \count($one) <=> \count($other);
    }

    /**
     * Return the sort key of a nullable value: its tag, then the value.
     *
     * @param  string|null  $value
     * @return list<int|string>
     */
    public static function nullable(?string $value): array
    {
        return $value === null ? [0, ''] : [1, $value];
    }

    /**
     * Return the key of the parts: each its length in bytes and its bytes, a
     * null as `~`, joined by `|`.
     *
     * @param  list<string|null>  $parts
     * @return string
     */
    public static function key(array $parts): string
    {
        return \implode('|', \array_map(static fn (?string $part): string => $part === null ? '~' : \strlen($part) . ':' . $part, $parts));
    }

    /**
     * Compare two parts of a sort key.
     *
     * @param  bool|int|string|null  $one
     * @param  bool|int|string|null  $other
     * @return int
     */
    private static function comparePart(bool|int|string|null $one, bool|int|string|null $other): int
    {
        if (\is_string($one) && \is_string($other)) {
            return \strcmp($one, $other) <=> 0;
        }

        return ($one === null ? -1 : (int) $one) <=> ($other === null ? -1 : (int) $other);
    }

    /**
     * Return the expression that orders the wrapped column byte for byte on the
     * driver.
     *
     * @param  string  $driver
     * @param  string  $wrapped
     * @return string
     */
    private static function bytes(string $driver, string $wrapped): string
    {
        return match ($driver) {
            'pgsql'            => "cast({$wrapped} as text) collate \"C\"",
            'mysql', 'mariadb' => "cast({$wrapped} as binary)",
            'sqlite'           => "{$wrapped} collate binary",
            default            => $wrapped,
        };
    }
}
