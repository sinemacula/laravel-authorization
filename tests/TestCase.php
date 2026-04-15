<?php

declare(strict_types = 1);

namespace Tests;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as OrchestraTestCase;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;

/**
 * Shared base test case for the package's Testbench-powered tests.
 *
 * Boots a minimal Testbench application with the authorization service
 * provider registered, an in-memory SQLite connection, and the shipped
 * `authorization` config block seeded. Subclasses may override
 * {@see self::defineEnvironment()} to adjust per-test config and
 * {@see self::defineDatabaseMigrations()} (or `setUp`) to create
 * additional tables.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class TestCase extends OrchestraTestCase
{
    /**
     * Register the package service provider.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    protected function getPackageProviders(mixed $app): array
    {
        return [
            AuthorizationServiceProvider::class,
        ];
    }

    /**
     * Seed the database connection and package config defaults.
     *
     * Reads `DB_CONNECTION` from the environment to select the driver.
     * Defaults to in-memory SQLite when unset, so local development
     * needs no extra configuration.
     *
     * @param  mixed  $app
     * @return void
     */
    protected function defineEnvironment(mixed $app): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', $this->databaseConnection());
    }

    /**
     * Build the database connection config from environment variables.
     *
     * @return array<string, mixed>
     */
    private function databaseConnection(): array
    {
        /** @var string $driver */
        $driver = env('DB_CONNECTION', 'sqlite');

        if ($driver === 'sqlite') {
            return [
                'driver'   => 'sqlite',
                'database' => ':memory:',
                'prefix'   => '',
            ];
        }

        return [
            'driver'    => $driver,
            'host'      => env('DB_HOST', '127.0.0.1'),
            'port'      => env('DB_PORT', $driver === 'pgsql' ? '5432' : '3306'),
            'database'  => env('DB_DATABASE', 'laravel_authorization_test'),
            'username'  => env('DB_USERNAME', 'root'),
            'password'  => env('DB_PASSWORD', ''),
            'prefix'    => '',
            'charset'   => $driver === 'pgsql' ? 'utf8' : 'utf8mb4',
            'collation' => $driver === 'pgsql' ? null : 'utf8mb4_unicode_ci',
        ];
    }

    /**
     * Run the package's shipped migrations and any fixture tables so
     * tests that persist roles, permissions, or policies have a
     * working schema.
     *
     * @return void
     */
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        Schema::create('stub_authorizables', static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('name')->nullable();
            $table->timestamps();
        });

        Schema::create('stub_second_authorizables', static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('name')->nullable();
            $table->timestamps();
        });

        if (env('DB_CONNECTION', 'sqlite') !== 'sqlite') {
            $this->beforeApplicationDestroyed(function (): void {
                /** @var \Illuminate\Config\Repository $config */
                $config = app(ConfigRepository::class);
                /** @var array<string, mixed> $tables */
                $tables = $config->array('authorization.tables', []);

                foreach ($tables as $table) {
                    if (is_string($table)) {
                        Schema::dropIfExists($table);
                    }
                }

                Schema::dropIfExists('stub_authorizables');
                Schema::dropIfExists('stub_second_authorizables');
            });
        }
    }
}
