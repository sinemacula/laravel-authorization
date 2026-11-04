<?php

declare(strict_types = 1);

namespace Tests;

// phpcs:disable PSR12.Files.FileHeader -- the shared formatter interleaves the
// function import with the class imports, which this sniff rejects.
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use function Orchestra\Testbench\load_migration_paths;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;

// phpcs:enable PSR12.Files.FileHeader

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

    /** @var array<string, true> Worker databases this process has created. */
    private static array $workerDatabases = [];

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
     * Register the package migration path on the migrator so `migrate:fresh`
     * picks it up.
     *
     * Uses `load_migration_paths` directly instead of `loadMigrationsFrom` so
     * Testbench never caches a per-test `MigrateProcessor` — which under
     * `RefreshDatabase` would otherwise run `migrate:rollback` in teardown and
     * fight the transactional rollback (fatal on Postgres once a test raises an
     * exception, silently corrupting state on MySQL).
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        load_migration_paths($this->app, __DIR__ . '/../database/migrations');
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
        $driver = getenv('DB_CONNECTION') ?: 'sqlite';

        if ($driver === 'sqlite') {
            return [
                'driver'   => 'sqlite',
                'database' => ':memory:',
                'prefix'   => '',
            ];
        }

        $connection = [
            'driver'    => $driver,
            'host'      => getenv('DB_HOST') ?: '127.0.0.1',
            'port'      => getenv('DB_PORT') ?: $this->defaultPort($driver),
            'database'  => getenv('DB_DATABASE') ?: 'laravel_authorization_test',
            'username'  => getenv('DB_USERNAME') ?: $this->defaultUsername($driver),
            'password'  => getenv('DB_PASSWORD') ?: '',
            'prefix'    => '',
            'charset'   => $driver === 'pgsql' ? 'utf8' : 'utf8mb4',
            'collation' => $driver === 'pgsql' ? null : 'utf8mb4_unicode_ci',
        ];

        $connection['database'] = $this->workerDatabase($connection);

        return $connection;
    }

    /**
     * Return the database this process tests against.
     *
     * Tests create, empty and drop the same tables, so paratest workers sharing
     * one database would collide. Each process gets its own database, named
     * after its paratest `TEST_TOKEN` (`0` outside paratest) and created afresh
     * on first use from a connection to the configured one, so nothing a
     * previous or interrupted run left behind reaches the next.
     *
     * @param  array{driver: string, host: string, port: string, database: string, username: string, password: string}  $connection
     * @return string
     */
    private function workerDatabase(array $connection): string
    {
        $token    = getenv('TEST_TOKEN');
        $database = $connection['database'] . '_' . ($token === false || $token === '' ? '0' : $token);

        if (isset(self::$workerDatabases[$database])) {
            return $database;
        }

        $dsn = sprintf('%s:host=%s;port=%s;dbname=%s', $connection['driver'], $connection['host'], $connection['port'], $connection['database']);
        $pdo = new \PDO($dsn, $connection['username'], $connection['password']);

        $quoted = $connection['driver'] === 'pgsql' ? '"' . $database . '"' : '`' . $database . '`';

        $pdo->exec('DROP DATABASE IF EXISTS ' . $quoted . ($connection['driver'] === 'pgsql' ? ' WITH (FORCE)' : ''));
        $pdo->exec('CREATE DATABASE ' . $quoted);

        self::$workerDatabases[$database] = true;

        return $database;
    }

    /**
     * Return the default database port for the given driver.
     *
     * @param  string  $driver
     * @return string
     */
    private function defaultPort(string $driver): string
    {
        return $driver === 'pgsql' ? '5432' : '3306';
    }

    /**
     * Return the default database username for the given driver.
     *
     * @param  string  $driver
     * @return string
     */
    private function defaultUsername(string $driver): string
    {
        return $driver === 'pgsql' ? 'postgres' : 'root';
    }
}
