<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query\Dialects;

use Illuminate\Database\Connection;
use SineMacula\Laravel\Authorization\Query\Contracts\Dialect;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;
use SineMacula\Laravel\Authorization\Query\QueryAuthorizer;

/**
 * The SQL `whereAuthorized()` writes on MySQL.
 *
 * A value is compared through its bytes, `CAST(x AS BINARY)`, which for an
 * integer are its decimal digits, as PHP reads them (an unsigned value beyond
 * PHP's integers included, which PHP reads as its digits), and for a utf8mb4
 * string the bytes PHP reads over a utf8mb4 connection, whatever the column's
 * collation; a `CHAR` loses its padding both in PHP and in the comparison. A
 * string column must be utf8mb4, and the connection's client, connection and
 * results character sets all utf8mb4. PHP reads every column of these kinds as
 * a string or an integer.
 *
 * The plain comparison an index serves compares a string column with the value
 * as a utf8mb4 literal, which takes the column's collation, under which equal
 * bytes are equal, and an integer column with the value's digits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MySqlDialect implements Dialect
{
    /** @var list<string> The integer types. */
    private const array INTEGERS = ['tinyint', 'smallint', 'mediumint', 'int', 'integer', 'bigint'];

    /** @var list<string> The string types, when their character set is utf8mb4. */
    private const array STRINGS = ['char', 'varchar', 'tinytext', 'text', 'mediumtext', 'longtext'];

    /**
     * Return the kind of a column by its type: the integer types are integers,
     * and the character and text types strings when their collation is a
     * utf8mb4 one.
     *
     * @param  array<string, mixed>  $column
     * @return \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind|null
     */
    #[\Override]
    public function kindOf(array $column): ?ColumnKind
    {
        $type      = \is_string($column['type_name'] ?? null) ? \strtolower($column['type_name']) : '';
        $collation = \is_string($column['collation'] ?? null) ? $column['collation'] : '';

        return match (true) {
            \in_array($type, self::INTEGERS, true)                                            => ColumnKind::INTEGER,
            \in_array($type, self::STRINGS, true) && \str_starts_with($collation, 'utf8mb4_') => ColumnKind::STRING,
            default                                                                           => null,
        };
    }

    /**
     * Determine whether the connection's client, connection and results
     * character sets are all utf8mb4.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return bool
     */
    #[\Override]
    public function isUtf8(Connection $connection): bool
    {
        $sets = (array) $connection->selectOne('select @@character_set_client as client, @@character_set_connection as connection, @@character_set_results as results');

        $names = \array_map(static fn (mixed $set): string => \is_string($set) ? \strtolower($set) : '', $sets);

        return $names !== [] && \array_diff($names, ['utf8mb4']) === [];
    }

    /**
     * Return the condition a row's key meets when it identifies a record.
     *
     * @param  string  $key
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind  $kind
     * @param  bool  $isIntegerCast
     * @return string
     */
    #[\Override]
    public function keyGuard(string $key, ColumnKind $kind, bool $isIntegerCast): string
    {
        return $kind === ColumnKind::STRING && !$isIntegerCast
            ? "({$key} IS NOT NULL AND OCTET_LENGTH({$key}) > 0 AND LOCATE(X'00', CAST({$key} AS BINARY)) = 0)"
            : "{$key} IS NOT NULL";
    }

    /**
     * Return the byte length of a row's key, which only a string's leaves
     * unbounded.
     *
     * @param  string  $key
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind  $kind
     * @param  bool  $isIntegerCast
     * @return string|null
     */
    #[\Override]
    public function keyLength(string $key, ColumnKind $kind, bool $isIntegerCast): ?string
    {
        return $kind === ColumnKind::STRING && !$isIntegerCast ? "OCTET_LENGTH({$key})" : null;
    }

    /**
     * Return the condition every row's tenant column meets, since PHP reads
     * each kind the scope compares as a string, an integer or null.
     *
     * @param  string  $column
     * @return string
     */
    #[\Override]
    public function readable(string $column): string
    {
        return QueryAuthorizer::EVERY_ROW;
    }

    /**
     * Return the condition a row's column meets when its bytes are exactly the
     * value's.
     *
     * @param  string  $column
     * @param  string  $value
     * @return string
     */
    #[\Override]
    public function equalsBytes(string $column, string $value): string
    {
        return "CAST({$column} AS BINARY) = X'" . \bin2hex($value) . '\'';
    }

    /**
     * Return a condition comparing the bare column with the value: a string
     * column with the value as a utf8mb4 literal, when it is UTF-8, which a
     * utf8mb4 column always holds; an integer column with its digits, when it
     * is an integer's decimal text, as PHP reads one.
     *
     * @param  string  $column
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind  $kind
     * @param  string  $value
     * @return string
     */
    #[\Override]
    public function equalsIndexed(string $column, ColumnKind $kind, string $value): string
    {
        return match (true) {
            $kind === ColumnKind::STRING  && \mb_check_encoding($value, 'UTF-8')                      => "{$column} = _utf8mb4 X'" . \bin2hex($value) . '\'',
            $kind === ColumnKind::INTEGER && \preg_match('/\A(?:0|-?[1-9]\d{0,19})\z/', $value) === 1 => "{$column} = {$value}",
            default                                                                                   => QueryAuthorizer::NO_ROW,
        };
    }

    /**
     * Determine whether the column compares byte for byte: it has no collation,
     * or `utf8mb4_0900_bin`, which compares bytes and does not pad, or
     * `binary`.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  array<string, mixed>  $column
     * @return bool
     */
    #[\Override]
    public function isExactCollation(Connection $connection, string $table, array $column): bool
    {
        $collation = $column['collation'] ?? null;

        return $collation === null || (\is_string($collation) && \in_array(\strtolower($collation), ['utf8mb4_0900_bin', 'binary'], true));
    }

    /**
     * Determine whether an integer key column holds only integers PHP reads as
     * they are: every type but an unsigned `BIGINT`, whose values beyond PHP's
     * largest integer PHP would read otherwise.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  array<string, mixed>  $column
     * @return bool
     */
    #[\Override]
    public function isExactInteger(Connection $connection, string $table, array $column): bool
    {
        $type = \is_string($column['type'] ?? null) ? \strtolower($column['type']) : '';

        return !(\str_starts_with($type, 'bigint') && \str_contains($type, 'unsigned'));
    }

    /**
     * Return the bytes of the expression's text as a utf8mb4 string: an
     * integer's decimal digits, and text as PHP reads it.
     *
     * @param  string  $expression
     * @return string
     */
    #[\Override]
    public function textImage(string $expression): string
    {
        return "CAST(CAST({$expression} AS CHAR CHARACTER SET utf8mb4) AS BINARY)";
    }

    /**
     * Return a binary string literal of the value's bytes.
     *
     * @param  string  $value
     * @return string
     */
    #[\Override]
    public function bytes(string $value): string
    {
        return 'X\'' . \bin2hex($value) . '\'';
    }

    /**
     * Return the condition a row's column meets when its bytes start with the
     * value's.
     *
     * @param  string  $column
     * @param  string  $value
     * @return string
     */
    #[\Override]
    public function startsWith(string $column, string $value): string
    {
        return "LEFT(CAST({$column} AS BINARY), " . \strlen($value) . ') = ' . $this->bytes($value);
    }

    /**
     * Return the condition an attachment's key column meets when it holds the
     * key's text, compared under the column's own utf8mb4 collation, as the
     * resolver's comparison with that text is; or null when the column has no
     * utf8mb4 collation.
     *
     * @param  string  $attached
     * @param  string  $key
     * @param  array<string, mixed>  $column
     * @param  bool  $isExact
     * @return string|null
     */
    #[\Override]
    public function equalsKeyText(string $attached, string $key, array $column, bool $isExact): ?string
    {
        $collation = \is_string($column['collation'] ?? null) ? \strtolower($column['collation']) : '';

        return \preg_match('/\Autf8mb4_[a-z0-9_]+\z/', $collation) === 1 ? "{$attached} = CAST({$key} AS CHAR CHARACTER SET utf8mb4) COLLATE {$collation}" : null;
    }
}
