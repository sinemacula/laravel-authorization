<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query\Dialects;

use SineMacula\Laravel\Authorization\Query\Contracts\Dialect;

/**
 * The dialect `whereAuthorized()` writes for each database driver it supports:
 * SQLite, PostgreSQL and MySQL. Any other driver, Laravel's `mariadb` included,
 * has none, so the scope refuses it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Dialects
{
    /**
     * Return the dialect of the driver, or null when the scope does not support
     * it.
     *
     * @param  string  $driver
     * @return \SineMacula\Laravel\Authorization\Query\Contracts\Dialect|null
     */
    public static function for(string $driver): ?Dialect
    {
        return match ($driver) {
            'sqlite' => new SqliteDialect,
            'pgsql'  => new PostgresDialect,
            'mysql'  => new MySqlDialect,
            default  => null,
        };
    }
}
