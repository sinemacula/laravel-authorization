<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query\Dialects;

use Illuminate\Database\Connection;
use SineMacula\Laravel\Authorization\Query\Contracts\Dialect;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;

/**
 * The SQL `whereAuthorized()` writes on SQLite.
 *
 * SQLite stores any value in any column, whatever its declared type, so nothing
 * here relies on the declared type: a value is compared through its bytes,
 * `CAST(x AS BLOB)`, which for an integer are its decimal digits, as PHP's
 * `(string)` gives them, and for text and blobs the bytes PHP reads. A real
 * number, which PHP reads as a float, never equals a tenant (the tenant
 * resolver refuses it), so a comparison admits integers, text and blobs alone.
 * The database must be UTF-8, as `PRAGMA encoding` reports it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SqliteDialect implements Dialect
{
    /**
     * Return the kind of a column by its declared type's affinity: integer for
     * a type naming `int`, string for one naming `char`, `clob` or `text`.
     *
     * @param  array<string, mixed>  $column
     * @return \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind|null
     */
    #[\Override]
    public function kindOf(array $column): ?ColumnKind
    {
        $type = \strtolower(\is_string($column['type'] ?? null) ? $column['type'] : '');

        return match (true) {
            \str_contains($type, 'int')                                                                  => ColumnKind::INTEGER,
            \str_contains($type, 'char') || \str_contains($type, 'clob') || \str_contains($type, 'text') => ColumnKind::STRING,
            default                                                                                      => null,
        };
    }

    /**
     * Determine whether the database is UTF-8.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return bool
     */
    #[\Override]
    public function isUtf8(Connection $connection): bool
    {
        $row = (array) $connection->selectOne('PRAGMA encoding');

        return \strtoupper((string) \reset($row)) === 'UTF-8'; // @phpstan-ignore cast.string
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
        // Any value cast to an integer is one; any other is read as SQLite
        // holds it, whatever the column's declared type.
        return $isIntegerCast
            ? "{$key} IS NOT NULL"
            : "({$key} IS NOT NULL AND length(CAST({$key} AS BLOB)) > 0 AND instr(CAST({$key} AS BLOB), X'00') = 0)";
    }

    /**
     * Return the byte length of a row's key, which only a cast to an integer
     * bounds on SQLite.
     *
     * @param  string  $key
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind  $kind
     * @param  bool  $isIntegerCast
     * @return string|null
     */
    #[\Override]
    public function keyLength(string $key, ColumnKind $kind, bool $isIntegerCast): ?string
    {
        return $isIntegerCast ? null : "length(CAST({$key} AS BLOB))";
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
        return "(typeof({$column}) IN ('integer', 'text', 'blob') AND CAST({$column} AS BLOB) = X'" . \bin2hex($value) . '\')';
    }
}
