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
 * `authorization` config block seeded. Subclasses may override the
 * environment and migration hooks to adjust per-test config or create
 * additional tables.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class TestCase extends OrchestraTestCase
{
    /** @var bool Process-level flag so the Testbench Blade view cache is cleared once per phpunit run. */
    private static bool $viewCacheCleared = false;

    /**
     * Clear Testbench's shared compiled-view cache once per phpunit
     * process. Blade compiles anonymous templates (including those
     * passed to `Blade::render()`) into
     * `vendor/orchestra/testbench-core/laravel/storage/framework/views/`
     * keyed by template-string hash. The directory persists across
     * runs, so a compiled template baked without a directive that
     * later gets registered keeps producing uncompiled output until
     * the cache is flushed. Clearing per-process keeps the fix cheap
     * (one sweep per worker, not per test).
     *
     * @return void
     */
    protected function setUp(): void
    {
        if (!self::$viewCacheCleared) {
            $views = __DIR__ . '/../vendor/orchestra/testbench-core/laravel/storage/framework/views';

            if (\is_dir($views)) {
                foreach (\glob($views . '/*.php') ?: [] as $file) {
                    @\unlink($file);
                }
            }

            self::$viewCacheCleared = true;
        }

        parent::setUp();
    }

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
     * Run the package's shipped migrations and any fixture tables so
     * tests that persist roles, permissions, or policies have a
     * working schema.
     *
     * @return void
     */
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        Schema::create('stub_identities', static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('name')->nullable();
            $table->timestamps();
        });

        Schema::create('stub_second_identities', static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('name')->nullable();
            $table->timestamps();
        });

        Schema::create('stub_tenants', static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('name')->nullable();
            $table->timestamps();
        });

        if (env('DB_CONNECTION', 'sqlite') !== 'sqlite') { // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig
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

                Schema::dropIfExists('stub_identities');
                Schema::dropIfExists('stub_second_identities');
                Schema::dropIfExists('stub_tenants');
            });
        }
    }

    /**
     * Build the database connection config from environment variables.
     *
     * @return array<string, mixed>
     */
    private function databaseConnection(): array
    {
        /** @var string $driver */
        $driver = env('DB_CONNECTION', 'sqlite'); // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig

        if ($driver === 'sqlite') {
            return [
                'driver'   => 'sqlite',
                'database' => ':memory:',
                'prefix'   => '',
            ];
        }

        return [
            'driver'    => $driver,
            'host'      => env('DB_HOST', '127.0.0.1'), // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig
            'port'      => env('DB_PORT', $driver === 'pgsql' ? '5432' : '3306'), // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig
            'database'  => env('DB_DATABASE', 'laravel_authorization_test'), // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig
            'username'  => env('DB_USERNAME', 'root'), // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig
            'password'  => env('DB_PASSWORD', ''), // @phpstan-ignore larastan.noEnvCallsOutsideOfConfig
            'prefix'    => '',
            'charset'   => $driver === 'pgsql' ? 'utf8' : 'utf8mb4',
            'collation' => $driver === 'pgsql' ? null : 'utf8mb4_unicode_ci',
        ];
    }
}
