<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query\Dialects;

use Illuminate\Database\Connection;
use SineMacula\Laravel\Authorization\Query\Contracts\Dialect;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;

/**
 * The SQL `whereAuthorized()` writes on MySQL.
 *
 * A value is compared through its bytes, `CAST(x AS BINARY)`, which for an
 * integer are its decimal digits, as PHP reads them (an unsigned value beyond
 * PHP's integers included, which PHP reads as its digits), and for a utf8mb4
 * string the bytes PHP reads over a utf8mb4 connection, whatever the column's
 * collation; a `CHAR` loses its padding both in PHP and in the comparison. A
 * string column must be utf8mb4, and the connection's client, connection and
 * results character sets all utf8mb4.
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
}
