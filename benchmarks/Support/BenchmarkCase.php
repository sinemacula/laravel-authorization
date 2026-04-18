<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\Foundation\Application as TestbenchApplication;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;

/**
 * Lightweight base class for benches that need a booted Laravel.
 *
 * Spins up a Testbench-backed application with the authorization
 * service provider registered, an in-memory SQLite connection, and
 * the shipped package migrations + stub identity table applied. Each
 * bench subclass calls `boot()` from its `@BeforeMethods` hook so the
 * container is ready before the first revolution.
 *
 * The class is deliberately not a PHPUnit base — benchmarks and tests
 * share nothing beyond a Testbench-powered Application, and pulling
 * in the PHPUnit hierarchy here would couple bench runs to the test
 * suite's lifecycle hooks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class BenchmarkCase
{
    /** @var \Illuminate\Foundation\Application|null The booted application instance — populated by `boot()`. */
    protected ?Application $app = null;

    /**
     * Boot a minimal Testbench application and run the package
     * migrations so benches have a working Eloquent schema.
     *
     * Idempotent: a previously booted app is returned as-is. This
     * lets `@BeforeMethods` be cheap when PHPBench rebuilds fixtures
     * per revolution.
     *
     * @return \Illuminate\Foundation\Application
     */
    protected function boot(): Application
    {
        if ($this->app !== null) {
            return $this->app;
        }

        /** @var \Illuminate\Foundation\Application $app */
        $app = TestbenchApplication::create(
            basePath: null,
            resolvingCallback: null,
            options: [
                'load_environment_variables' => false,
                'extra'                      => [
                    'providers' => [AuthorizationServiceProvider::class],
                ],
            ],
        );

        $this->app = $app;

        $this->configureDatabase($app);
        $this->runMigrations();

        return $app;
    }

    /**
     * Configure an in-memory SQLite connection on the booted app.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    private function configureDatabase(Application $app): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);
        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);
    }

    /**
     * Run the package migrations plus a small stub-identity table
     * used by benches that need a persistable principal.
     *
     * @return void
     */
    private function runMigrations(): void
    {
        $migrationsPath = __DIR__ . '/../../database/migrations';
        $files          = \glob($migrationsPath . '/*.php');

        if ($files === false) {
            return;
        }

        \sort($files);

        foreach ($files as $file) {

            // Laravel migrations are anonymous-class returning files
            // that expose no class symbol for `use` — dynamic include
            // is the idiomatic Laravel loader and matches the shape
            // of `Illuminate\Database\Migrations\Migrator::resolve()`.
            $migration = include_once $file; // NOSONAR

            if (\is_object($migration) && \method_exists($migration, 'up')) {
                $migration->up();
            }
        }

        if (!Schema::hasTable('bench_identities')) {
            Schema::create('bench_identities', static function (Blueprint $table): void {
                $table->string('id')->primary();
                $table->string('name')->nullable();
                $table->timestamps();
            });
        }
    }
}
