<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use Illuminate\Database\Connection;
use SineMacula\Laravel\Authorization\Query\Contracts\Dialect;

/**
 * Reads what `whereAuthorized()` needs to know about a model's table and
 * connection, and about the authorization tables, once for each: the columns of
 * a table, as the schema builder describes them, whether a column compares byte
 * for byte, whether an integer key holds only what PHP reads, and whether the
 * connection is UTF-8.
 *
 * The service provider binds it scoped, so a request or job reads each table
 * and connection once however many queries it scopes, and the next one reads
 * them afresh.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SchemaInspector
{
    /** @var array<string, array<string, array<string, mixed>>> The columns of each table read, keyed by connection and table, then by name. */
    private array $columns = [];

    /** @var array<string, bool> Whether each connection read is UTF-8, by name. */
    private array $utf8 = [];

    /** @var array<string, bool> Whether each column read is exact, keyed by what is asked, connection, table and column. */
    private array $exact = [];

    /**
     * Return the columns of the table, keyed by name.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @return array<string, array<string, mixed>>
     */
    public function columns(Connection $connection, string $table): array
    {
        return $this->columns[$connection->getName() . "\0" . $table] ??= self::read($connection, $table);
    }

    /**
     * Determine whether the connection is UTF-8, as the dialect asks it.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\Authorization\Query\Contracts\Dialect  $dialect
     * @return bool
     */
    public function isUtf8(Connection $connection, Dialect $dialect): bool
    {
        return $this->utf8[(string) $connection->getName()] ??= $dialect->isUtf8($connection);
    }

    /**
     * Determine whether the column of the table compares byte for byte, as the
     * dialect asks it; a missing column does not.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\Authorization\Query\Contracts\Dialect  $dialect
     * @param  string  $table
     * @param  string  $column
     * @return bool
     */
    public function isExactCollation(Connection $connection, Dialect $dialect, string $table, string $column): bool
    {
        $described = $this->columns($connection, $table)[$column] ?? null;

        return $this->exact["collation\0{$connection->getName()}\0{$table}\0{$column}"] ??= $described !== null && $dialect->isExactCollation($connection, $table, $described);
    }

    /**
     * Determine whether the integer column of the table holds only integers PHP
     * reads as they are, as the dialect asks it; a missing column does not.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\Authorization\Query\Contracts\Dialect  $dialect
     * @param  string  $table
     * @param  string  $column
     * @return bool
     */
    public function isExactInteger(Connection $connection, Dialect $dialect, string $table, string $column): bool
    {
        $described = $this->columns($connection, $table)[$column] ?? null;

        return $this->exact["integer\0{$connection->getName()}\0{$table}\0{$column}"] ??= $described !== null && $dialect->isExactInteger($connection, $table, $described);
    }

    /**
     * Read the columns of the table, keyed by name.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @return array<string, array<string, mixed>>
     */
    private static function read(Connection $connection, string $table): array
    {
        $columns = [];

        foreach ($connection->getSchemaBuilder()->getColumns($table) as $column) {
            /** @var array<string, mixed> $column */
            $name = $column['name'] ?? null;

            $columns[\is_string($name) ? $name : ''] = $column;
        }

        return $columns;
    }
}
