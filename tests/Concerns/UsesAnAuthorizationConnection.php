<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository;
use Illuminate\Database\Connection;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Moves the package's tables onto a second connection for the current test.
 *
 * Registers an in-memory SQLite connection named `authorization`, points
 * `authorization.connection` at it and runs every shipped migration, so the
 * tables exist there as well as on the default connection the test case
 * migrated. The connection is SQLite whatever the default connection is, and it
 * is set up inside the test rather than when the application boots, so the
 * default connection's schema is never touched.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait UsesAnAuthorizationConnection
{
    /**
     * Register the second connection, select it for the package and create the
     * package's tables on it.
     *
     * @return void
     */
    protected function useAnAuthorizationConnection(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(Repository::class);

        $config->set('database.connections.authorization', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        $config->set('authorization.connection', 'authorization');

        foreach (self::packageMigrations() as $migration) {
            \assert(\method_exists($migration, 'up'));

            $migration->up();
        }
    }

    /**
     * Reverse every shipped migration, in the reverse of the order they run.
     *
     * @return void
     */
    protected function reversePackageMigrations(): void
    {
        foreach (\array_reverse(self::packageMigrations()) as $migration) {
            \assert(\method_exists($migration, 'down'));

            $migration->down();
        }
    }

    /**
     * Return the second connection.
     *
     * @return \Illuminate\Database\Connection
     */
    protected static function authorizationConnection(): Connection
    {
        /** @var \Illuminate\Database\Connection */
        return DB::connection('authorization');
    }

    /**
     * Return a fresh instance of every shipped migration, in the order they
     * run.
     *
     * @return list<\Illuminate\Database\Migrations\Migration>
     */
    protected static function packageMigrations(): array
    {
        $files = \glob(__DIR__ . '/../../database/migrations/*.php') ?: [];

        \sort($files);

        return \array_map(static function (string $file): Migration {
            /** @var \Illuminate\Database\Migrations\Migration $migration */
            $migration = require $file;

            return $migration;
        }, $files);
    }
}
