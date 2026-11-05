<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Database;

use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;

/**
 * The database connection the package's tables live on.
 *
 * Read from `authorization.connection`. Null, the default, puts the tables on
 * the application's default connection. Every package model and pivot reads and
 * writes on this connection, every shipped migration creates and drops its
 * table on it, and the package's own transactions run on it, so a host
 * application can keep the authorization tables on the connection its other
 * identity tables use and commit them together.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuthorizationConnection
{
    /**
     * Return the configured connection name, or null for the application's
     * default connection. An empty name counts as unset, so an empty
     * environment variable selects the default connection.
     *
     * @return string|null
     */
    public static function name(): ?string
    {
        $name = config('authorization.connection');

        return \is_string($name) && $name !== '' ? $name : null;
    }

    /**
     * Return the connection a package model or pivot reads and writes on: the
     * configured connection, else the instance's own, else the application's
     * default.
     *
     * The default is named rather than left to Laravel, because Laravel gives a
     * related model or a pivot that names no connection the connection of the
     * model the relation starts from, which for a grant is the grantee's. A
     * pivot passes no connection of its own, since the one it carries is always
     * that inherited one.
     *
     * @param  string|null  $instance
     * @return string
     */
    public static function resolve(?string $instance = null): string
    {
        return self::name() ?? $instance ?? DB::getDefaultConnection();
    }

    /**
     * Return the connection the package's pivots and transactions use: the
     * configured connection, else the application's default.
     *
     * @return \Illuminate\Database\Connection
     */
    public static function connection(): Connection
    {
        /** @var \Illuminate\Database\Connection */
        return DB::connection(self::resolve());
    }
}
