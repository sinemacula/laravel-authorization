<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Connection;
use Illuminate\Database\MariaDbConnection;
use Illuminate\Database\MySqlConnection;
use Illuminate\Database\PostgresConnection;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\SQLiteConnection;

/**
 * Builds queries on a connection of each supported driver that never connects,
 * its PDO never asked for, so a test can compare the SQL a query compiles to on
 * every driver's grammar, whichever database the test itself runs on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait CompilesQueries
{
    /**
     * Return the drivers whose grammars a query is compiled for.
     *
     * @return list<string>
     */
    protected static function drivers(): array
    {
        return ['sqlite', 'pgsql', 'mysql', 'mariadb'];
    }

    /**
     * Return a query of the table on a connection of the driver that never
     * connects.
     *
     * @param  string  $driver
     * @param  string  $table
     * @return \Illuminate\Database\Query\Builder
     */
    protected static function queryOn(string $driver, string $table): Builder
    {
        return self::connectionOf($driver)->query()->from($table);
    }

    /**
     * Return the wrapped column, as the driver's grammar writes it.
     *
     * @param  string  $driver
     * @param  string  $column
     * @return string
     */
    protected static function wrappedOn(string $driver, string $column): string
    {
        return self::connectionOf($driver)->getQueryGrammar()->wrap($column);
    }

    /**
     * Return a connection of the driver that never connects.
     *
     * @param  string  $driver
     * @return \Illuminate\Database\Connection
     */
    private static function connectionOf(string $driver): Connection
    {
        $pdo    = static fn (): \PDO => throw new \LogicException('The connection compiles queries; it never runs one.');
        $config = ['driver' => $driver, 'name' => $driver];

        return match ($driver) {
            'pgsql'   => new PostgresConnection($pdo, 'reviews', '', $config),
            'mysql'   => new MySqlConnection($pdo, 'reviews', '', $config),
            'mariadb' => new MariaDbConnection($pdo, 'reviews', '', $config),
            default   => new SQLiteConnection($pdo, ':memory:', '', $config),
        };
    }
}
