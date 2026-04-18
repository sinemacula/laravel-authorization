<?php

declare(strict_types = 1);

namespace Tests;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as OrchestraTestCase;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;

/**
 * Shared base test case for the package's Testbench-powered tests.
 *
 * Boots a minimal Testbench application with the authorization service provider
 * registered and a driver selected via `DB_CONNECTION`. Uses Laravel's
 * `RefreshDatabase` trait so migrations run once per phpunit process and every
 * test wraps its work in a rolled-back transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class TestCase extends OrchestraTestCase
{
    use RefreshDatabase;

    /** @var bool Process-level flag so the Testbench Blade view cache is cleared once per phpunit run. */
    private static bool $viewCacheCleared = false;

    /**
     * Clear Testbench's shared compiled-view cache once per phpunit process.
     * Blade compiles anonymous templates (including those passed to
     * `Blade::render()`) into
     * `vendor/orchestra/testbench-core/laravel/storage/framework/views/` keyed
     * by template-string hash. The directory persists across runs, so a
     * compiled template baked without a directive that later gets registered
     * keeps producing uncompiled output until the cache is flushed. Clearing
     * per-process keeps the fix cheap (one sweep per worker, not per test).
     *
     * @return void
     */
    #[\Override]
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
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [
            AuthorizationServiceProvider::class,
        ];
    }

    /**
     * Seed the database connection and package config defaults.
     *
     * Reads `DB_CONNECTION` from the environment to select the driver. Defaults
     * to in-memory SQLite when unset, so local development needs no extra
     * configuration.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', $this->databaseConnection());
    }

    /**
     * Register the package migration path so `migrate:fresh` picks it up.
     *
     * Under `RefreshDatabase` this only registers the path on the first test;
     * subsequent tests skip the re-registration and reuse the cached schema.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
    }

    /**
     * Create fixture tables that live outside the package migrations after the
     * `migrate:fresh` run has completed.
     *
     * Fires on the `DatabaseRefreshed` event, so the stub tables get created
     * exactly once per phpunit process alongside the package schema.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrationsAfterDatabaseRefreshed(): void
    {
        $this->createStubIdentityTables();
    }

    /**
     * Create the `stub_*` fixture tables that back the test-only identity
     * models.
     *
     * @return void
     */
    private function createStubIdentityTables(): void
    {
        foreach (['stub_identities', 'stub_second_identities', 'stub_tenants'] as $table) {
            Schema::create($table, static function (Blueprint $schema): void {
                $schema->string('id')->primary();
                $schema->string('name')->nullable();
                $schema->timestamps();
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
