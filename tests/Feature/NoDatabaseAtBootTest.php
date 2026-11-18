<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use Orchestra\Testbench\TestCase as OrchestraTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\PlanContextSource;
use Tests\Feature\Stubs\RecordingPermissionProvider;
use Tests\Feature\Stubs\RecordingResourceAttributes;
use Tests\Feature\Stubs\RecordingSubjectAttributes;
use Tests\Feature\Stubs\StubPolicyStore;
use Tests\Feature\Stubs\StubSessionPolicySource;

/**
 * Registering and booting the provider never queries or writes the database.
 *
 * The application boots on an empty in-memory database with no package tables,
 * a permission enum and a permission provider configured, and every optional
 * feature too in one case, as `config:cache`, `route:cache` and `migrate` boot
 * it on a fresh deployment. Booting succeeds and runs no query.
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
     */
    public function testBootRunsNoQueryWithoutTables(): void
    {
        self::assertSame([], $this->queriesRegisteringThePackage());
        self::assertSame(0, RecordingPermissionProvider::$reads);
        self::assertFalse(Schema::hasTable('permissions'));
    }

    /**
     * Booting with every optional feature configured, on a connection of its
     * own, and no tables, runs no query.
     *
     * @return void
     */
    #[DefineEnvironment('configureEveryFeature')]
    public function testBootWithEveryFeatureConfiguredRunsNoQuery(): void
    {
        self::assertSame([], $this->queriesRegisteringThePackage());
        self::assertFalse(Schema::hasTable('permissions'));
        self::assertFalse(Schema::connection('authorization')->hasTable('permissions'));
    }

    /**
     * Configure usage tracking, break-glass, a persistent cache and policy
     * store, session scopes, sensitive actions, attribute providers, a context
     * source and a connection of the package's own.
     *
     * @param  mixed  $app
     * @return void
     */
    protected function configureEveryFeature(mixed $app): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('database.connections.authorization', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $config->set('authorization.connection', 'authorization');
        $config->set('authorization.policy_store', StubPolicyStore::class);
        $config->set('authorization.cache.store', 'array');
        $config->set('authorization.usage', ['enabled' => true, 'connection' => 'sync', 'queue' => 'usage']);
        $config->set('authorization.break_glass', ['enabled' => true, 'roles' => ['responder' => ['max_minutes' => 30]], 'justifications' => ['incident'], 'notes' => true]);
        $config->set('authorization.session', ['source' => StubSessionPolicySource::class, 'scopes' => ['editor' => ['posts:create']]]);
        $config->set('authorization.events.decisions.sensitive_actions', ['posts:delete']);
        $config->set('authorization.attributes', ['resources' => ['post' => RecordingResourceAttributes::class], 'subjects' => ['user' => RecordingSubjectAttributes::class]]);
        $config->set('authorization.context.sources', [PlanContextSource::class]);
    }

    /**
     * Use an empty in-memory database, whatever the suite's driver, and
     * configure an enum and a provider before the package registers.
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

    /**
     * Register and boot the package and return every query that ran meanwhile.
     *
     * @return list<string>
     *
     * @throws \LogicException
     */
    private function queriesRegisteringThePackage(): array
    {
        $app     = $this->app ?? throw new \LogicException('The application has not been created.');
        $queries = [];

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $app->register(AuthorizationServiceProvider::class);

        return $queries;
    }
}
