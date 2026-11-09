<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Illuminate\Database\Query\Builder;

/**
 * The keyset an access review resumes a query from: the rows after a position
 * in the review's order (see `ReviewOrder`), never an offset, so a page costs
 * the same queries whatever its number, and a row present throughout a scan is
 * read exactly once.
 *
 * A position holds one value for each column the query is ordered by, in that
 * order, as a row's sort key holds them: a text column its string, compared
 * byte for byte; a nullable column (`TAGGED`) its tag and its value, a null
 * (tag 0) before any value (tag 1); a boolean column (`FLAG`) its value, false
 * before true. The condition is written as the order is read, column by column:
 * a row is after the position when its first column is greater, or equal and
 * the rest are after, and, when asked, a row at the position itself is kept
 * too. The leading text columns are bounded together as well (see
 * `ReviewOrder::atLeast()`), a bound the condition already implies, so where an
 * index leads with them it seeks to the position instead of reading every row
 * before it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Keyset
{
    /** @var string A text column, compared byte for byte. */
    public const string TEXT = 'text';

    /** @var string A nullable text column, a null before any value. */
    public const string TAGGED = 'tagged';

    /** @var string A boolean column, false before true. */
    public const string FLAG = 'flag';

    /**
     * Limit the query to the rows after the position in the order of the
     * columns, each named with its kind, and to the row at the position too
     * when asked.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  list<array{string, string}>  $columns
     * @param  list<bool|int|string|null>  $position
     * @param  bool  $isInclusive
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \UnexpectedValueException
     */
    public static function after(Builder $query, array $columns, array $position, bool $isInclusive = false): Builder
    {
        $terms = self::terms($columns, $position);

        $query->where(static function (Builder $after) use ($terms, $isInclusive): void {
            self::from($after, $terms, $isInclusive);
        });

        return ReviewOrder::atLeast($query, self::leading($terms));
    }

    /**
     * Return the value of each of the terms' leading text columns, by column,
     * up to the first column of any other kind.
     *
     * @param  list<array{string, string, bool|string|null}>  $terms
     * @return array<string, string>
     */
    private static function leading(array $terms): array
    {
        $values = [];

        foreach ($terms as [$column, $kind, $value]) {
            if ($kind !== self::TEXT) {
                break;
            }

            $values[$column] = (string) $value;
        }

        return $values;
    }

    /**
     * Write the condition that the row is after the position from the first of
     * the terms on: its column greater, or equal and the rest after; with no
     * term left, the row is at the position, kept only when asked.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  list<array{string, string, bool|string|null}>  $terms
     * @param  bool  $isInclusive
     * @return void
     */
    private static function from(Builder $query, array $terms, bool $isInclusive): void
    {
        $term = \array_shift($terms);

        if ($term === null) {
            $query->whereRaw($isInclusive ? '1 = 1' : '1 = 0');

            return;
        }

        self::greater($query, $term);

        $query->orWhere(static function (Builder $same) use ($term, $terms, $isInclusive): void {
            self::equal($same, $term);

            $same->where(static function (Builder $rest) use ($terms, $isInclusive): void {
                self::from($rest, $terms, $isInclusive);
            });
        });
    }

    /**
     * Return each column with its kind and its value from the position: a text
     * column's string, a nullable column's value or null by its tag, a boolean
     * column's value.
     *
     * @param  list<array{string, string}>  $columns
     * @param  list<bool|int|string|null>  $position
     * @return list<array{string, string, bool|string|null}>
     *
     * @throws \UnexpectedValueException
     */
    private static function terms(array $columns, array $position): array
    {
        $terms = [];
        $index = 0;

        foreach ($columns as [$column, $kind]) {
            $value = $position[$index] ?? null;

            if ($kind === self::TAGGED) {
                $value = ($value === 1 || $value === true) ? ($position[$index + 1] ?? '') : null;
                $index++;
            }

            $terms[] = [$column, $kind, self::valueOf($kind, $value)];
            $index++;
        }

        if ($index !== \count($position)) {
            throw new \UnexpectedValueException('A keyset position holds one value for each column it is ordered by.');
        }

        return $terms;
    }

    /**
     * Return the value of a term of the kind: a boolean for a boolean column, a
     * string or null for a nullable one, a string for a text column.
     *
     * @param  string  $kind
     * @param  bool|int|string|null  $value
     * @return bool|string|null
     */
    private static function valueOf(string $kind, bool|int|string|null $value): bool|string|null
    {
        return match (true) {
            $kind === self::FLAG                      => \in_array($value, [true, 1, '1'], true),
            $kind === self::TAGGED && $value === null => null,
            default                                   => (string) $value,
        };
    }

    /**
     * Write the condition that the row's column is greater than the term's
     * value: a value after a null, a greater string byte for byte, true after
     * false.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  array{string, string, bool|string|null}  $term
     * @return void
     */
    private static function greater(Builder $query, array $term): void
    {
        [$column, $kind, $value] = $term;

        match (true) {
            $kind  === self::FLAG => $value === true ? $query->whereRaw('1 = 0') : $query->where($column, true),
            $value === null       => $query->whereNotNull($column),
            default               => ReviewOrder::compared($query, $column, '>', (string) $value),
        };
    }

    /**
     * Write the condition that the row's column equals the term's value: a null
     * for a null, the same bytes for a string, the same boolean.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  array{string, string, bool|string|null}  $term
     * @return void
     */
    private static function equal(Builder $query, array $term): void
    {
        [$column, $kind, $value] = $term;

        match (true) {
            $kind  === self::FLAG => $query->where($column, $value === true),
            $value === null       => $query->whereNull($column),
            default               => ReviewOrder::compared($query, $column, '=', (string) $value),
        };
    }
}
