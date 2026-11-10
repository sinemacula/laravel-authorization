<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as OrchestraTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\RecordingPermissionProvider;

/**
 * Booting the provider never queries or writes the database.
 *
 * The application boots on an empty in-memory database with no package tables,
 * a permission enum and a permission provider configured, as `config:cache`,
 * `route:cache` and `migrate` boot it on a fresh deployment. Booting succeeds,
 * runs no query and never reads the provider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationServiceProvider::class)]
final class NoDatabaseAtBootTest extends OrchestraTestCase
{
    /**
     * Booting with a provider and an enum configured, and no tables, runs no
     * query and never reads the provider.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testBootRunsNoQueryWithoutTables(): void
    {
        $queries = [];

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        (new AuthorizationServiceProvider($this->app ?? throw new \LogicException('The application has not been created.')))->boot();

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

        $config->set('database.default', 'boot');
        $config->set('database.connections.boot', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);
        $config->set('authorization.permission_providers', [RecordingPermissionProvider::class]);

        RecordingPermissionProvider::$reads = 0;
    }
}
