<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Database;

/**
 * The database connection the package's tables live on.
 *
 * Read from `authorization.connection`. Null, the default, leaves the choice to
 * Laravel, so the tables live on the application's default connection. Every
 * package model and pivot reads and writes on this connection, every shipped
 * migration creates and drops its table on it, and the package's own
 * transactions run on it, so a host application can keep the authorization
 * tables on the connection its other identity tables use and commit them
 * together.
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
}
