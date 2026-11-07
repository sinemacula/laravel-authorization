<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query\Contracts;

use Illuminate\Database\Connection;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;

/**
 * The SQL `whereAuthorized()` writes on one database, each fragment proved to
 * hold exactly when PHP, reading the row, would find the same (N65): the kind
 * of a column, whether the connection is UTF-8, the guard on a record's key,
 * its byte length, whether PHP can read a tenant column, and the byte-exact
 * comparison of a column with a value, with the plain comparison an index can
 * serve that keeps every row the exact one does.
 *
 * Every fragment is written without bindings: a value is inlined as the hex of
 * its bytes, or as digits or a uuid it has been proved to be, so it never needs
 * escaping and can never misalign the bindings of the query it joins.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface Dialect
{
    /**
     * Return the kind of a column as the schema builder describes it, or null
     * when the scope cannot compare it exactly.
     *
     * @param  array<string, mixed>  $column
     * @return \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind|null
     */
    public function kindOf(array $column): ?ColumnKind;

    /**
     * Determine whether the connection, and the database behind it, hand PHP
     * the UTF-8 bytes the database compares.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return bool
     */
    public function isUtf8(Connection $connection): bool;

    /**
     * Return the condition a row's key meets when `check()` can identify the
     * record: it is not null, and, unless PHP casts it to an integer or the
     * column cannot hold one, its text is not empty and holds no NUL byte.
     *
     * @param  string  $key
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind  $kind
     * @param  bool  $isIntegerCast
     * @return string
     */
    public function keyGuard(string $key, ColumnKind $kind, bool $isIntegerCast): string;

    /**
     * Return the byte length of the text PHP reads from a row's key, or null
     * when it is bounded by its kind, at most 64 bytes.
     *
     * @param  string  $key
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind  $kind
     * @param  bool  $isIntegerCast
     * @return string|null
     */
    public function keyLength(string $key, ColumnKind $kind, bool $isIntegerCast): ?string;

    /**
     * Return the condition a row's tenant column meets when PHP reads it as a
     * string, an integer or null, as the tenant resolver requires.
     *
     * @param  string  $column
     * @return string
     */
    public function readable(string $column): string;

    /**
     * Return the condition a row's column meets when the text PHP reads from it
     * is exactly the value, byte for byte.
     *
     * @param  string  $column
     * @param  string  $value
     * @return string
     */
    public function equalsBytes(string $column, string $value): string;

    /**
     * Return a condition comparing the bare column of the kind with the value,
     * which an index on the column can serve, met by every row whose column
     * `equalsBytes()` finds holds exactly the value; the condition no row meets
     * when no value of the kind can be it.
     *
     * @param  string  $column
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind  $kind
     * @param  string  $value
     * @return string
     */
    public function equalsIndexed(string $column, ColumnKind $kind, string $value): string;
}
