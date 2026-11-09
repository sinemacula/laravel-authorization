<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authorization\Database\ExactReferences;

/**
 * The one order an access review lists its rows in, the same on SQLite,
 * PostgreSQL and MySQL: a total order over the source kind (in the order
 * `Enums\SourceKind` declares them), the target, the grantee, the origin scope
 * and the route.
 *
 * Every string is compared byte for byte, as PHP's `strcmp()` compares it, so
 * neither a database's collation nor its locale moves a row: SQLite compares
 * with its binary collation, PostgreSQL through the `C` collation, and MySQL as
 * binary strings. A reference column (see `Database\ExactReferences`) is
 * compared as it is stored wherever that is already byte for byte: on MySQL,
 * whose reference columns are collated `utf8mb4_0900_bin`, it is left bare, and
 * on PostgreSQL, whose reference columns are text, it is only collated `C`, so
 * an index on the column, or on that expression, serves both the order and the
 * keyset; any other column is cast first. Each nullable component is tagged
 * first, a null before any value, so the platform comes before every tenant and
 * every application before a named one, whatever a database does with nulls. A
 * boolean orders false before true.
 *
 * A key is built the same way from its parts: each part its length in bytes and
 * its bytes, a null as `~`, so no two lists of parts share a key, whatever
 * bytes they hold.
 *
 * A keyset compares a column with a value through the same expression (see
 * `compared()`), so a page resumes exactly where the order says the page before
 * ended, on every database; on PostgreSQL, the leading columns of a keyset are
 * also bounded together, as a row (see `atLeast()`), so an index on them seeks
 * to where the page starts rather than filtering every row before it.
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

        return $query->orderByRaw(self::bytes(self::driverOf($query), $column, $wrapped));
    }

    /**
     * Limit the query to the rows whose column compares to the value, byte for
     * byte, as the operator says: `=` or `>`, as the review's order compares
     * them, so a keyset resumes exactly where a page ended on every database.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $column
     * @param  string  $operator
     * @param  string  $value
     * @return \Illuminate\Database\Query\Builder
     */
    public static function compared(Builder $query, string $column, string $operator, string $value): Builder
    {
        $driver = self::driverOf($query);
        $bound  = self::isCastToBinary($driver, $column) ? 'cast(? as binary)' : '?';

        return $query->whereRaw(self::bytes($driver, $column, $query->getGrammar()->wrap($column)) . ' ' . ($operator === '>' ? '>' : '=') . ' ' . $bound, [$value]);
    }

    /**
     * Limit the query, on PostgreSQL, to the rows whose columns, taken together
     * as a row, compare at or after the values, byte for byte: a bound a keyset
     * already implies, written so an index leading with those columns seeks to
     * it; on any other database the query is left as it is, since its keyset is
     * already one an index seeks by.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  array<string, string>  $values
     * @return \Illuminate\Database\Query\Builder
     */
    public static function atLeast(Builder $query, array $values): Builder
    {
        if ($values === [] || self::driverOf($query) !== 'pgsql') {
            return $query;
        }

        $grammar = $query->getGrammar();
        $columns = \array_map(static fn (string $column): string => self::bytes('pgsql', $column, $grammar->wrap($column)), \array_keys($values));
        $marks   = \implode(', ', \array_fill(0, \count($values), '?'));

        return $query->whereRaw('(' . \implode(', ', $columns) . ') >= (' . $marks . ')', \array_values($values));
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
     * Return the name of the driver the query runs on, or none when its
     * connection is not a database connection.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return string
     */
    private static function driverOf(Builder $query): string
    {
        $connection = $query->getConnection();

        return $connection instanceof Connection ? $connection->getDriverName() : '';
    }

    /**
     * Return the expression that orders the column, wrapped as given, byte for
     * byte on the driver: a reference column as it is stored where that is
     * already byte for byte, or only collated, any other column cast first; a
     * driver it does not know orders the column as it is.
     *
     * @param  string  $driver
     * @param  string  $column
     * @param  string  $wrapped
     * @return string
     */
    private static function bytes(string $driver, string $column, string $wrapped): string
    {
        return match (true) {
            $driver === 'pgsql'                    => (self::isReference($column) ? $wrapped : "cast({$wrapped} as text)") . ' collate "C"',
            self::isCastToBinary($driver, $column) => "cast({$wrapped} as binary)",
            $driver === 'sqlite'                   => "{$wrapped} collate binary",
            default                                => $wrapped,
        };
    }

    /**
     * Determine whether the column is compared as a binary string on the
     * driver: every column on MariaDB, and every column but a reference column
     * on MySQL, whose reference columns compare their bytes already.
     *
     * @param  string  $driver
     * @param  string  $column
     * @return bool
     */
    private static function isCastToBinary(string $driver, string $column): bool
    {
        return $driver === 'mariadb' || ($driver === 'mysql' && !self::isReference($column));
    }

    /**
     * Determine whether the column, named alone or after its table, is one of
     * the package's reference columns (see `Database\ExactReferences`).
     *
     * @param  string  $column
     * @return bool
     */
    private static function isReference(string $column): bool
    {
        return \in_array(Str::afterLast($column, '.'), ExactReferences::COLUMNS, true);
    }
}
