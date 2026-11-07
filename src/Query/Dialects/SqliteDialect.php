<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query\Dialects;

use Illuminate\Database\Connection;
use SineMacula\Laravel\Authorization\Query\Contracts\Dialect;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;

/**
 * The SQL an authorized scope writes on SQLite.
 *
 * SQLite stores any value in any column, whatever its declared type, so nothing
 * here relies on the declared type: a value is compared through its bytes,
 * `CAST(x AS BLOB)`, which for an integer are its decimal digits, as PHP's
 * `(string)` gives them, and for text and blobs the bytes PHP reads. A real
 * number, which PHP reads as a float, never equals a tenant (the tenant
 * resolver refuses it), so a comparison admits integers, text and blobs alone,
 * and a row of no tenant is kept only when neither tenant column holds one. The
 * database must be UTF-8, as `PRAGMA encoding` reports it.
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
     * Return the condition a row's tenant column meets when it holds no real
     * number, which PHP reads as a float.
     *
     * @param  string  $column
     * @return string
     */
    #[\Override]
    public function readable(string $column): string
    {
        return "typeof({$column}) IN ('null', 'integer', 'text', 'blob')";
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

    /**
     * Return a condition comparing the bare column with the value as text and
     * as a blob, whatever the column's kind: the column's affinity turns the
     * text into the integer an integer row holds, and its collation keeps every
     * row of the same bytes.
     *
     * @param  string  $column
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind  $kind
     * @param  string  $value
     * @return string
     */
    #[\Override]
    public function equalsIndexed(string $column, ColumnKind $kind, string $value): string
    {
        $hex = \bin2hex($value);

        return "{$column} IN (CAST(X'{$hex}' AS TEXT), X'{$hex}')";
    }

    /**
     * Determine whether the column compares byte for byte: it declares no
     * collation, or `BINARY`.
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

        return $collation === null || (\is_string($collation) && \strtolower($collation) === 'binary');
    }

    /**
     * Determine whether an integer key column is the table's rowid, declared
     * `INTEGER PRIMARY KEY` on a table with a rowid: any other column of an
     * integer type may hold a real number or text, which PHP reads otherwise. A
     * column declared `INTEGER PRIMARY KEY DESC` is not the rowid, and SQLite
     * gives it an index of its own, as it gives every primary key but the
     * rowid, so a table whose primary key has an index is refused.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  array<string, mixed>  $column
     * @return bool
     */
    #[\Override]
    public function isExactInteger(Connection $connection, string $table, array $column): bool
    {
        if (($column['auto_increment'] ?? false) !== true) {
            return false;
        }

        $table   = $connection->getTablePrefix() . $table;
        $row     = (array) $connection->selectOne('select sql from sqlite_master where type = \'table\' and name = ?', [$table]);
        $sql     = $row['sql'] ?? null;
        $indexes = $connection->select('PRAGMA index_list("' . \str_replace('"', '""', $table) . '")');
        $isKeyed = \array_filter($indexes, static fn (mixed $index): bool => (((array) $index)['origin'] ?? null) === 'pk') !== [];

        return \is_string($sql) && \preg_match('/\bwithout\s+rowid\b/i', $sql) !== 1 && !$isKeyed;
    }

    /**
     * Return the bytes of the expression's text: an integer's decimal digits,
     * and the bytes of text or a blob.
     *
     * @param  string  $expression
     * @return string
     */
    #[\Override]
    public function textImage(string $expression): string
    {
        return "CAST({$expression} AS BLOB)";
    }

    /**
     * Return a blob literal of the value's bytes.
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
        return 'substr(' . $this->textImage($column) . ', 1, ' . \strlen($value) . ') = ' . $this->bytes($value);
    }

    /**
     * Return the condition an attachment's key column meets when it holds the
     * key's text, compared byte for byte, as the column's `BINARY` collation
     * compares it; or null when the column declares another collation.
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
        return $isExact ? "{$attached} = CAST({$key} AS TEXT) COLLATE BINARY" : null;
    }

    /**
     * Return a literal SQLite reads as it reads the value bound: null, an
     * integer's digits (a boolean as Laravel binds it, `1` or `0`), and a
     * string as text of its bytes with no affinity, as a bound string has.
     *
     * @param  mixed  $value
     * @return string|null
     */
    #[\Override]
    public function parameter(mixed $value): ?string
    {
        return match (true) {
            $value === null    => 'NULL',
            \is_bool($value)   => $value ? '1' : '0',
            \is_int($value)    => $value < 0 ? "({$value})" : (string) $value,
            \is_string($value) => '+CAST(' . $this->bytes($value) . ' AS TEXT)',
            default            => null,
        };
    }
}
