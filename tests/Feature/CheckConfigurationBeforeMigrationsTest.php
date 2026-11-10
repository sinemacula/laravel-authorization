<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as OrchestraTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Console\CheckConfigurationCommand;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\RecordingPermissionProvider;

/**
 * `authorization:check` on an application whose migrations have not run.
 *
 * The application boots on an empty in-memory database with no package tables,
 * a permission enum and a permission provider configured, as on a fresh
 * deployment before `migrate`. The report, as text and as JSON, runs no query,
 * never reads the provider and passes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckConfigurationCommand::class)]
final class CheckConfigurationBeforeMigrationsTest extends OrchestraTestCase
{
    /**
     * The command runs no query and never reads the permission provider before
     * the migrations have run, and every check passes.
     *
     * @return void
     */
    public function testTheCommandRunsNoQueryBeforeMigrations(): void
    {
        $queries = [];

        DB::listen(static function (object $query) use (&$queries): void {
            $queries[] = $query;
        });

        self::assertSame(0, Artisan::call(CheckConfigurationCommand::NAME));
        self::assertStringEndsWith("Every check passed.\n", Artisan::output());
        self::assertSame(0, Artisan::call(CheckConfigurationCommand::NAME, ['--format' => 'json']));
        self::assertStringContainsString('"connectivity": "not_tested"', Artisan::output());
        self::assertSame([], $queries);
        self::assertSame(0, RecordingPermissionProvider::$reads);
        self::assertFalse(Schema::hasTable('permissions'));
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
        return [AuthorizationServiceProvider::class];
    }

    /**
     * Use an empty in-memory database, whatever the suite's driver, and
     * configure an enum and a provider before the application boots.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('database.default', 'fresh');
        $config->set('database.connections.fresh', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);
        $config->set('authorization.permission_providers', [RecordingPermissionProvider::class]);

        RecordingPermissionProvider::$reads = 0;
    }
}
