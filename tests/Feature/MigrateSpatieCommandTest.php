<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\Builder as SchemaBuilder;
use Illuminate\Foundation\Testing\RefreshDatabaseState;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Console\MigrateSpatieCommand;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Events\Grantee\PermissionGranted;
use SineMacula\Laravel\Authorization\Events\Grantee\RoleAssigned;
use SineMacula\Laravel\Authorization\Events\Permission\Created as PermissionCreated;
use SineMacula\Laravel\Authorization\Events\Role\Created as RoleCreated;
use SineMacula\Laravel\Authorization\Events\Role\PermissionGranted as RolePermissionGranted;
use SineMacula\Laravel\Authorization\Exceptions\GrantRefusedException;
use SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\UndeclaredPermissionException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\GrantScopeQuery;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Testing\FakeTenantTree;
use Tests\Concerns\DeclaresPermissions;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Concerns\WidensGrants;
use Tests\Fixtures\GrantHooks\RefusingGrantHook;
use Tests\TestCase;

/**
 * Feature tests for the `authorization:migrate-spatie` Artisan command.
 *
 * To avoid table-name collisions between Spatie's default schema and this
 * package's defaults (both use `roles`, `permissions`), the test configures the
 * package to use `auth_`-prefixed target table names. This mirrors the
 * real-world scenario where a consumer configures different table names before
 * running the migration.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(MigrateSpatieCommand::class)]
final class MigrateSpatieCommandTest extends TestCase
{
    use DeclaresPermissions, UsesAnAuthorizationConnection, WidensGrants;

    /** @var string The Spatie role ID used by the string-keyed fixture. */
    private const string STRING_ROLE_ID = '0192f0c4-3b1a-7d2e-9a4b-1c2d3e4f5a6b';

    /** @var string The Spatie permission ID used by the string-keyed fixture. */
    private const string STRING_PERMISSION_ID = '0192f0c4-3b1a-7d2e-9a4b-6b5a4f3e2d1c';

    /**
     * Create the Spatie and package tables, then seed Spatie data.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        // This suite overrides `authorization.tables.*` to use the `auth_`
        // prefix (see defineEnvironment), so the migrated schema differs from
        // the shared default. Flip the RefreshDatabase migration flag back to
        // false to force `migrate:fresh` under this suite's config.
        RefreshDatabaseState::$migrated = false;

        parent::setUp();

        $this->createSpatieTables();
        $this->seedSpatieData();
    }

    /**
     * Drop the Spatie-style fixture tables so they do not leak across tests on
     * persistent-connection drivers (MySQL / Postgres). The shipped
     * `TestCase::defineDatabaseMigrations()` already drops the package's own
     * tables via `authorization.tables`; this hook cleans up the Spatie-style
     * tables the migration command reads.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (['model_has_permissions', 'model_has_roles', 'role_has_permissions', 'permissions', 'roles'] as $table) {
            Schema::dropIfExists($table);
        }

        parent::tearDown();

        // Flip the RefreshDatabase migration flag back to false so the next
        // test re-runs `migrate:fresh` under its own `authorization.tables.*`
        // config rather than inheriting this suite's `auth_`-prefixed schema.
        RefreshDatabaseState::$migrated = false;
    }

    /**
     * The command is registered under its `NAME` constant, the name its
     * signature declares.
     *
     * @return void
     */
    public function testTheCommandsNameIsItsConstant(): void
    {
        self::assertSame('authorization:migrate-spatie', MigrateSpatieCommand::NAME);
        self::assertInstanceOf(MigrateSpatieCommand::class, Artisan::all()[MigrateSpatieCommand::NAME] ?? null);
        self::assertSame(MigrateSpatieCommand::NAME, Artisan::all()[MigrateSpatieCommand::NAME]->getName());
    }

    /**
     * Full migration copies all five Spatie tables into the package tables.
     *
     * @return void
     */
    public function testMigratesAllSpatieTablesSuccessfully(): void
    {
        $exitCode = Artisan::call('authorization:migrate-spatie');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Migration summary', $output);
        self::assertSame(2, DB::table('auth_roles')->count());
        self::assertSame(3, DB::table('auth_permissions')->count());
        self::assertSame(2, DB::table('auth_role_permissions')->count());
        self::assertSame(1, DB::table('auth_authorizable_roles')->count());
        self::assertSame(1, DB::table('auth_authorizable_permissions')->count());
    }

    /**
     * A Spatie grant with no team id is imported platform-wide, for every
     * application, stamped with the time of the import.
     *
     * @return void
     */
    public function testImportedGrantsArePlatformWideAndStamped(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        try {
            Artisan::call('authorization:migrate-spatie');
        } finally {
            Carbon::setTestNow();
        }

        foreach (['auth_authorizable_roles', 'auth_authorizable_permissions'] as $table) {
            $row = DB::table($table)->sole();

            self::assertNull($row->tenant_type, $table);
            self::assertNull($row->application, $table);
            self::assertSame('2026-07-01 12:00:00', Carbon::parse((string) $row->created_at)->format('Y-m-d H:i:s'), $table);
            self::assertSame('2026-07-01 12:00:00', Carbon::parse((string) $row->updated_at)->format('Y-m-d H:i:s'), $table);
        }
    }

    /**
     * Every row is written through the management services, so each role,
     * permission and grant is reported as any other write is, the grantee by
     * Spatie's type and id. A dry run reports nothing.
     *
     * @return void
     */
    public function testImportsThroughTheServices(): void
    {
        $events = [RoleCreated::class, PermissionCreated::class, RolePermissionGranted::class, RoleAssigned::class, PermissionGranted::class];

        Event::fake($events);

        Artisan::call('authorization:migrate-spatie', ['--dry-run' => true]);

        foreach ($events as $event) {
            Event::assertNotDispatched($event);
        }

        Artisan::call('authorization:migrate-spatie');

        Event::assertDispatchedTimes(RoleCreated::class, 2);
        Event::assertDispatchedTimes(PermissionCreated::class, 3);
        Event::assertDispatchedTimes(RolePermissionGranted::class, 2);
        Event::assertDispatched(RoleAssigned::class, static fn (RoleAssigned $event): bool => $event->grantee->type === 'App\Models\User'
            && $event->grantee->id                                                                                  === '42'
            && $event->name                                                                                         === 'admin');
        Event::assertDispatchedTimes(PermissionGranted::class, 1);
    }

    /**
     * With `authorization.connection` set, Spatie's tables are read on the
     * default connection and every row is written on the package's connection,
     * none on the default one.
     *
     * @return void
     */
    public function testWritesOnThePackageConnection(): void
    {
        $this->useAnAuthorizationConnection();

        self::assertSame(0, Artisan::call('authorization:migrate-spatie'));

        $counts = [
            'auth_roles'                    => 2,
            'auth_permissions'              => 3,
            'auth_role_permissions'         => 2,
            'auth_authorizable_roles'       => 1,
            'auth_authorizable_permissions' => 1,
        ];

        foreach ($counts as $table => $count) {
            self::assertSame($count, self::authorizationConnection()->table($table)->count(), $table);
            self::assertSame(0, DB::table($table)->count(), $table);
        }
    }

    /**
     * The import runs in one transaction on the package's connection: when a
     * write fails part-way, the rows written before it are rolled back there.
     * The permission's kept id collides with a row the package's table already
     * holds, after the role has been written.
     *
     * @return void
     */
    public function testAFailedImportIsRolledBackOnThePackageConnection(): void
    {
        $this->useAnAuthorizationConnection();
        $this->recreateSpatieTablesWithStringIds();

        self::authorizationConnection()->table('auth_permissions')->insert(['id' => self::STRING_PERMISSION_ID, 'name' => 'other', 'guard' => 'web']);

        $failure = null;

        try {
            Artisan::call('authorization:migrate-spatie');
        } catch (\Throwable $exception) {
            $failure = $exception;
        }

        self::assertInstanceOf(QueryException::class, $failure);
        self::assertSame(0, self::authorizationConnection()->table('auth_roles')->count());
        self::assertSame(['other'], self::authorizationConnection()->table('auth_permissions')->pluck('name')->all());
    }

    /**
     * A second run over the same source writes nothing, dispatches nothing and
     * reports every row as already present.
     *
     * @return void
     */
    public function testARerunAfterAFullRunChangesNothing(): void
    {
        self::assertSame(0, Artisan::call('authorization:migrate-spatie'));

        $before = self::targetRows();
        $events = [RoleCreated::class, PermissionCreated::class, RolePermissionGranted::class, RoleAssigned::class, PermissionGranted::class];

        Event::fake($events);

        self::assertSame(0, Artisan::call('authorization:migrate-spatie'));

        $output = Artisan::output();

        foreach ($events as $event) {
            Event::assertNotDispatched($event);
        }

        self::assertSame($before, self::targetRows());
        self::assertMatchesRegularExpression('/\|\s+Target Table\s+\|\s+Rows\s+\|\s+Already Present\s+\|/', $output);

        foreach (['roles' => 2, 'permissions' => 3, 'role_permissions' => 2, 'authorizable_roles' => 1, 'authorizable_permissions' => 1] as $table => $present) {
            self::assertMatchesRegularExpression("/\\|\\s+{$table}\\s+\\|\\s+0\\s+\\|\\s+{$present}\\s+\\|/", $output);
        }
    }

    /**
     * A run a grant hook stopped after the catalogue committed is carried on by
     * a re-run, which reuses the roles and permissions and makes the grants.
     *
     * @return void
     */
    public function testARerunAfterAPartialRunCarriesOn(): void
    {
        $this->useAnAuthorizationConnection();

        [, [$principal]] = $this->principals('person', ['42']);

        foreach (['model_has_roles', 'model_has_permissions'] as $table) {
            DB::table($table)->update(['model_type' => $principal->getMorphClass()]);
        }

        $this->app?->instance(GrantHook::class, new RefusingGrantHook);

        $failure = null;

        try {
            Artisan::call('authorization:migrate-spatie');
        } catch (\Throwable $exception) {
            $failure = $exception;
        }

        self::assertInstanceOf(GrantRefusedException::class, $failure);
        self::assertSame(0, self::authorizationConnection()->table('auth_authorizable_roles')->count());

        $this->hook();

        self::assertSame(0, Artisan::call('authorization:migrate-spatie'));

        $output = Artisan::output();

        self::assertSame(2, self::authorizationConnection()->table('auth_roles')->count());
        self::assertSame(3, self::authorizationConnection()->table('auth_permissions')->count());
        self::assertSame(2, self::authorizationConnection()->table('auth_role_permissions')->count());
        self::assertSame(1, self::authorizationConnection()->table('auth_authorizable_roles')->count());
        self::assertSame(1, self::authorizationConnection()->table('auth_authorizable_permissions')->count());
        self::assertMatchesRegularExpression('/\|\s+roles\s+\|\s+0\s+\|\s+2\s+\|/', $output);
        self::assertMatchesRegularExpression('/\|\s+authorizable_roles\s+\|\s+1\s+\|\s+0\s+\|/', $output);
    }

    /**
     * Only the platform's row of the same name and guard is reused: a role of
     * another guard, or owned by a tenant, is left alone and a new one made.
     *
     * @return void
     */
    public function testReusesOnlyThePlatformRowOfTheSameNameAndGuard(): void
    {
        $editorId = '0192f0c4-3b1a-7d2e-9a4b-000000000001';

        DB::table('auth_roles')->insert([
            ['id' => $editorId, 'name' => 'editor', 'guard' => 'web', 'tenant_type' => null, 'tenant_id' => null],
            ['id' => '0192f0c4-3b1a-7d2e-9a4b-000000000002', 'name' => 'admin', 'guard' => 'api', 'tenant_type' => null, 'tenant_id' => null],
            ['id' => '0192f0c4-3b1a-7d2e-9a4b-000000000003', 'name' => 'admin', 'guard' => 'web', 'tenant_type' => 'team', 'tenant_id' => '1'],
        ]);

        self::assertSame(0, TenantScope::within(new Reference('team', '1'), null, static fn (): int => Artisan::call('authorization:migrate-spatie')));

        $adminId = DB::table('auth_roles')->where('name', 'admin')->where('guard', 'web')->whereNull('tenant_type')->value('id');

        self::assertIsString($adminId);
        self::assertSame(4, DB::table('auth_roles')->count());
        self::assertSame([$editorId], DB::table('auth_roles')->where('name', 'editor')->pluck('id')->all());
        self::assertSame([$adminId], DB::table('auth_authorizable_roles')->pluck('role_id')->all());
        self::assertMatchesRegularExpression('/\|\s+roles\s+\|\s+1\s+\|\s+1\s+\|/', Artisan::output());
    }

    /**
     * Return a Spatie table and a name it already holds on the `web` guard,
     * with the refusal a second row of that name and guard gives.
     *
     * @return iterable<string, array{string, string, string}>
     */
    public static function duplicateSpatieRows(): iterable
    {
        yield 'role' => ['roles', 'admin', 'Spatie roles 1 and 8 both map to role \'admin\' with guard \'web\'.'];
        yield 'permission' => ['permissions', 'posts:edit', 'Spatie permissions 2 and 8 both map to permission \'posts:edit\' with guard \'web\'.'];
    }

    /**
     * Two Spatie rows that map to the same role or permission stop the import,
     * a dry run too, before anything is written; the same name on another guard
     * does not.
     *
     * @param  string  $table
     * @param  string  $name
     * @param  string  $message
     * @return void
     */
    #[DataProvider('duplicateSpatieRows')]
    public function testTwoSpatieRowsOfTheSameNameAndGuardStopTheImport(string $table, string $name, string $message): void
    {
        $this->useAnAuthorizationConnection();

        DB::table($table)->insert(['id' => 7, 'name' => $name, 'guard_name' => 'api', 'created_at' => now(), 'updated_at' => now()]);

        self::assertSame(0, Artisan::call('authorization:migrate-spatie', ['--dry-run' => true]));

        DB::table($table)->insert(['id' => 8, 'name' => $name, 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()]);

        foreach ([['--dry-run' => true], []] as $options) {
            $failure = null;

            try {
                Artisan::call('authorization:migrate-spatie', $options);
            } catch (\Throwable $exception) {
                $failure = $exception;
            }

            self::assertInstanceOf(\UnexpectedValueException::class, $failure);
            self::assertSame($message, $failure->getMessage());
        }

        self::assertSame(0, self::authorizationConnection()->table('auth_roles')->count());
        self::assertSame(0, self::authorizationConnection()->table('auth_permissions')->count());
    }

    /**
     * The options name Spatie's tables and their connection: the tables they
     * name are read, the defaults are not, and a table named as a package table
     * on another connection is no collision. A dry run reads them too.
     *
     * @return void
     */
    public function testReadsTheTablesAndConnectionTheOptionsName(): void
    {
        $this->app?->make(ConfigRepository::class)->set('database.connections.spatie', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);

        $tables = [
            'roles'                 => 'auth_roles',
            'permissions'           => 'legacy_permissions',
            'role_has_permissions'  => 'legacy_role_has_permissions',
            'model_has_roles'       => 'legacy_model_has_roles',
            'model_has_permissions' => 'legacy_model_has_permissions',
        ];

        $spatie = DB::connection('spatie');

        $this->createSpatieTables($spatie->getSchemaBuilder(), $tables);

        $spatie->table('auth_roles')->insert(['id' => 1, 'name' => 'auditor', 'guard_name' => 'web']);
        $spatie->table('legacy_permissions')->insert(['id' => 1, 'name' => 'reports:read', 'guard_name' => 'web']);
        $spatie->table('legacy_role_has_permissions')->insert(['permission_id' => 1, 'role_id' => 1]);
        $spatie->table('legacy_model_has_roles')->insert(['role_id' => 1, 'model_type' => 'App\Models\User', 'model_id' => 7]);
        $spatie->table('legacy_model_has_permissions')->insert(['permission_id' => 1, 'model_type' => 'App\Models\User', 'model_id' => 7]);

        $options = [
            '--connection'                  => 'spatie',
            '--roles-table'                 => 'auth_roles',
            '--permissions-table'           => 'legacy_permissions',
            '--role-has-permissions-table'  => 'legacy_role_has_permissions',
            '--model-has-roles-table'       => 'legacy_model_has_roles',
            '--model-has-permissions-table' => 'legacy_model_has_permissions',
        ];

        self::assertSame(0, Artisan::call('authorization:migrate-spatie', [...$options, '--dry-run' => true]));
        self::assertMatchesRegularExpression('/\|\s+roles\s+\|\s+1\s+\|\s+0\s+\|/', Artisan::output());
        self::assertSame(0, DB::table('auth_roles')->count());

        self::assertSame(0, Artisan::call('authorization:migrate-spatie', $options));
        self::assertSame(['auditor'], DB::table('auth_roles')->pluck('name')->all());
        self::assertSame(['reports:read'], DB::table('auth_permissions')->pluck('name')->all());
        self::assertSame(1, DB::table('auth_role_permissions')->count());
        self::assertSame(['7'], DB::table('auth_authorizable_roles')->pluck('authorizable_id')->all());
        self::assertSame(['7'], DB::table('auth_authorizable_permissions')->pluck('authorizable_id')->all());
    }

    /**
     * A source table that is one of the package's tables on the same connection
     * is refused before anything is read, naming the option to set, dry run or
     * not; with the defaults this is Spatie's `roles`.
     *
     * @return void
     */
    public function testRefusesASourceTableThatIsAPackageTable(): void
    {
        Schema::drop('model_has_roles');

        $connection = DB::connection()->getName();

        self::assertSame(1, Artisan::call('authorization:migrate-spatie', ['--model-has-roles-table' => 'auth_authorizable_roles', '--dry-run' => true]));
        self::assertStringContainsString(
            "Spatie source table 'auth_authorizable_roles' is one of this package's tables on connection '{$connection}'. Pass --model-has-roles-table or --connection",
            Artisan::output(),
        );

        $this->app?->make(ConfigRepository::class)->set('authorization.tables.roles', 'roles');

        self::assertSame(1, Artisan::call('authorization:migrate-spatie'));
        self::assertStringContainsString(
            "Spatie source table 'roles' is one of this package's tables on connection '{$connection}'. Pass --roles-table or --connection to name Spatie's table.",
            Artisan::output(),
        );
        self::assertSame(0, DB::table('auth_roles')->count());
    }

    /**
     * A dry run after a full run reports the roles and permissions as already
     * present and writes nothing.
     *
     * @return void
     */
    public function testADryRunAfterAFullRunReportsTheCatalogueAsPresent(): void
    {
        Artisan::call('authorization:migrate-spatie');

        $before = self::targetRows();

        self::assertSame(0, Artisan::call('authorization:migrate-spatie', ['--dry-run' => true]));

        $output = Artisan::output();

        self::assertMatchesRegularExpression('/\|\s+roles\s+\|\s+0\s+\|\s+2\s+\|/', $output);
        self::assertMatchesRegularExpression('/\|\s+permissions\s+\|\s+0\s+\|\s+3\s+\|/', $output);
        self::assertSame($before, self::targetRows());
    }

    /**
     * Each grant is made as a call of its own once the roles, permissions and
     * roles' permissions have committed, so its grant hook runs with no other
     * transaction open on the package's connection, and so before any lock the
     * package takes for it, never under the locks of the rows imported before.
     *
     * @return void
     */
    public function testEachGrantRunsItsHookOnceTheCatalogueHasCommitted(): void
    {
        $this->useAnAuthorizationConnection();

        [, [$principal]] = $this->principals('person', ['42']);

        foreach (['model_has_roles', 'model_has_permissions'] as $table) {
            DB::table($table)->update(['model_type' => $principal->getMorphClass()]);
        }

        /** @var \ArrayObject<int, array{int, int, int}> $seen */
        $seen = new \ArrayObject;
        $hook = $this->hook(static function () use ($seen): void {
            $connection = self::authorizationConnection();

            $seen->append([$connection->transactionLevel(), $connection->table('auth_roles')->count(), $connection->table('auth_role_permissions')->count()]);
        });

        self::assertSame(0, Artisan::call('authorization:migrate-spatie'));
        self::assertSame([[1, 2, 2], [1, 2, 2]], $seen->getArrayCopy());
        self::assertSame([['platform'], ['platform']], $hook->reasons());
        self::assertSame(1, self::authorizationConnection()->table('auth_authorizable_roles')->where('authorizable_id', '42')->count());
        self::assertSame(1, self::authorizationConnection()->table('auth_authorizable_permissions')->where('authorizable_id', '42')->count());
    }

    /**
     * A grant a hook refuses stops the import: the roles, permissions and
     * roles' permissions, committed first, stay, and no grant is written.
     *
     * @return void
     */
    public function testAGrantAHookRefusesStopsTheImportAfterTheCatalogue(): void
    {
        $this->useAnAuthorizationConnection();

        [, [$principal]] = $this->principals('person', ['42']);

        DB::table('model_has_roles')->update(['model_type' => $principal->getMorphClass()]);

        $this->app?->instance(GrantHook::class, new RefusingGrantHook);

        $failure = null;

        try {
            Artisan::call('authorization:migrate-spatie');
        } catch (\Throwable $exception) {
            $failure = $exception;
        }

        self::assertInstanceOf(GrantRefusedException::class, $failure);
        self::assertSame(2, self::authorizationConnection()->table('auth_roles')->count());
        self::assertSame(2, self::authorizationConnection()->table('auth_role_permissions')->count());
        self::assertSame(0, self::authorizationConnection()->table('auth_authorizable_roles')->count());
        self::assertSame(0, self::authorizationConnection()->table('auth_authorizable_permissions')->count());
    }

    /**
     * The target tables are looked for on the package's connection: with it set
     * to a connection that has none, the import stops before writing.
     *
     * @return void
     */
    public function testLooksForTheTargetTablesOnThePackageConnection(): void
    {
        $this->useAnAuthorizationConnection();
        $this->reversePackageMigrations();

        self::assertSame(1, Artisan::call('authorization:migrate-spatie'));
        self::assertStringContainsString('Target table \'auth_roles\' does not exist', Artisan::output());
        self::assertSame(0, DB::table('auth_roles')->count());
    }

    /**
     * Role names are preserved during migration.
     *
     * @return void
     */
    public function testRoleNamesArePreserved(): void
    {
        $exitCode = Artisan::call('authorization:migrate-spatie');

        self::assertSame(0, $exitCode);

        $roleNames = DB::table('auth_roles')->pluck('name')->sort()->values()->all();

        self::assertSame(['admin', 'editor'], $roleNames);
    }

    /**
     * Permission names are preserved during migration.
     *
     * @return void
     */
    public function testPermissionNamesArePreserved(): void
    {
        $exitCode = Artisan::call('authorization:migrate-spatie');

        self::assertSame(0, $exitCode);

        $permissionNames = DB::table('auth_permissions')->pluck('name')->sort()->values()->all();

        self::assertSame(['posts:create', 'posts:delete', 'posts:edit'], $permissionNames);
    }

    /**
     * Morphic mappings are preserved (model_type -> authorizable_type).
     *
     * @return void
     */
    public function testMorphicMappingsArePreserved(): void
    {
        Artisan::call('authorization:migrate-spatie');

        $roleAssignment = DB::table('auth_authorizable_roles')->first();
        self::assertNotNull($roleAssignment);
        self::assertSame('App\Models\User', $roleAssignment->authorizable_type);
        self::assertSame('42', $roleAssignment->authorizable_id);

        $permAssignment = DB::table('auth_authorizable_permissions')->first();
        self::assertNotNull($permAssignment);
        self::assertSame('App\Models\User', $permAssignment->authorizable_type);
        self::assertSame('42', $permAssignment->authorizable_id);
    }

    /**
     * UUIDs are generated for Spatie auto-increment IDs.
     *
     * @return void
     */
    public function testUuidsAreGeneratedForAutoIncrementIds(): void
    {
        Artisan::call('authorization:migrate-spatie');

        $ids = [
            ...DB::table('auth_roles')->pluck('id')->all(),
            ...DB::table('auth_permissions')->pluck('id')->all(),
        ];

        self::assertCount(5, $ids);
        self::assertCount(5, \array_unique(\array_filter($ids, \is_string(...))));

        foreach ($ids as $id) {
            self::assertIsString($id);
            self::assertMatchesRegularExpression(
                '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',
                $id,
            );
        }
    }

    /**
     * The grants reference the generated role and permission UUIDs, not the
     * Spatie auto-increment IDs.
     *
     * @return void
     */
    public function testGrantsReferenceTheGeneratedUuids(): void
    {
        Artisan::call('authorization:migrate-spatie');

        $adminId  = DB::table('auth_roles')->where('name', 'admin')->value('id');
        $createId = DB::table('auth_permissions')->where('name', 'posts:create')->value('id');
        $editId   = DB::table('auth_permissions')->where('name', 'posts:edit')->value('id');
        $deleteId = DB::table('auth_permissions')->where('name', 'posts:delete')->value('id');

        self::assertIsString($adminId);
        self::assertIsString($createId);
        self::assertIsString($editId);
        self::assertIsString($deleteId);
        self::assertTrue(Str::isUuid($adminId));
        self::assertTrue(Str::isUuid($createId));
        self::assertTrue(Str::isUuid($editId));
        self::assertTrue(Str::isUuid($deleteId));
        self::assertSame([$adminId], DB::table('auth_authorizable_roles')->pluck('role_id')->all());
        self::assertSame([$editId], DB::table('auth_authorizable_permissions')->pluck('permission_id')->all());
        self::assertEqualsCanonicalizing(
            [[$adminId, $createId], [$adminId, $deleteId]],
            DB::table('auth_role_permissions')
                ->get(['role_id', 'permission_id'])
                ->map(static fn (object $row): array => [$row->role_id, $row->permission_id])
                ->all(),
        );
    }

    /**
     * Spatie string IDs (a UUID-keyed Spatie install) are kept as they are, and
     * the grants reference them unchanged.
     *
     * @return void
     */
    public function testStringIdsAreKeptAsTheyAre(): void
    {
        $this->recreateSpatieTablesWithStringIds();

        $exitCode = Artisan::call('authorization:migrate-spatie');

        self::assertSame(0, $exitCode);
        self::assertSame(
            [self::STRING_ROLE_ID => 'admin'],
            DB::table('auth_roles')->pluck('name', 'id')->all(),
        );
        self::assertSame(
            [self::STRING_PERMISSION_ID => 'posts:edit'],
            DB::table('auth_permissions')->pluck('name', 'id')->all(),
        );
        self::assertSame(
            [self::STRING_PERMISSION_ID => self::STRING_ROLE_ID],
            DB::table('auth_role_permissions')->pluck('role_id', 'permission_id')->all(),
        );
        self::assertSame([self::STRING_ROLE_ID], DB::table('auth_authorizable_roles')->pluck('role_id')->all());
        self::assertSame(
            [self::STRING_PERMISSION_ID],
            DB::table('auth_authorizable_permissions')->pluck('permission_id')->all(),
        );
    }

    /**
     * Role-permission pivot relationships are correctly mapped.
     *
     * @return void
     */
    public function testRolePermissionPivotsAreMapped(): void
    {
        Artisan::call('authorization:migrate-spatie');

        $adminId = DB::table('auth_roles')->where('name', 'admin')->value('id');

        $pivotPermissionIds = DB::table('auth_role_permissions')
            ->where('role_id', $adminId)
            ->pluck('permission_id')
            ->all();

        $permissionNames = DB::table('auth_permissions')
            ->whereIn('id', $pivotPermissionIds)
            ->pluck('name')
            ->sort()
            ->values()
            ->all();

        self::assertSame(['posts:create', 'posts:delete'], $permissionNames);
    }

    /**
     * Dry run reports counts without writing data.
     *
     * @return void
     */
    public function testDryRunReportsCountsWithoutWriting(): void
    {
        $exitCode = Artisan::call('authorization:migrate-spatie', ['--dry-run' => true]);
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Dry run', $output);
        self::assertStringContainsString('Migration summary', $output);
        self::assertSame(0, DB::table('auth_roles')->count());
        self::assertSame(0, DB::table('auth_permissions')->count());
        self::assertSame(0, DB::table('auth_role_permissions')->count());
        self::assertSame(0, DB::table('auth_authorizable_roles')->count());
        self::assertSame(0, DB::table('auth_authorizable_permissions')->count());
    }

    /**
     * Dotted names are valid package names and are migrated with their grants.
     *
     * @return void
     */
    public function testDottedNamesAreMigrated(): void
    {
        $this->seedNamesForValidation();

        Artisan::call('authorization:migrate-spatie');

        $managerId = DB::table('auth_roles')->where('name', 'content.manager')->value('id');
        $publishId = DB::table('auth_permissions')->where('name', 'posts.publish')->value('id');

        self::assertIsString($managerId);
        self::assertIsString($publishId);
        self::assertSame(
            [$publishId],
            DB::table('auth_role_permissions')->where('role_id', $managerId)->pluck('permission_id')->all(),
        );
    }

    /**
     * Role and permission names the package refuses are reported and skipped
     * together with every grant that references them, while the rows after them
     * are still migrated.
     *
     * @return void
     */
    public function testRefusedNamesAreReportedAndSkippedWithTheirGrants(): void
    {
        $this->seedNamesForValidation();

        $exitCode = Artisan::call('authorization:migrate-spatie');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString(self::refusalLine('role', 'has space'), $output);
        self::assertStringContainsString(self::refusalLine('permission', 'posts?edit'), $output);
        self::assertSame(
            ['admin', 'content.manager', 'editor'],
            DB::table('auth_roles')->pluck('name')->sort()->values()->all(),
        );
        self::assertSame(
            ['posts.publish', 'posts:create', 'posts:delete', 'posts:edit'],
            DB::table('auth_permissions')->pluck('name')->sort()->values()->all(),
        );
        self::assertSame(3, DB::table('auth_role_permissions')->count());
        self::assertSame(1, DB::table('auth_authorizable_roles')->count());
        self::assertSame(1, DB::table('auth_authorizable_permissions')->count());
    }

    /**
     * A grant that follows one skipped with its refused role or permission is
     * still migrated.
     *
     * @return void
     */
    public function testGrantsAfterASkippedGrantAreMigrated(): void
    {
        $this->seedNamesForValidation();

        DB::table('model_has_roles')->insert([
            ['role_id' => 2, 'model_type' => 'App\Models\User', 'model_id' => 8],
        ]);

        DB::table('model_has_permissions')->insert([
            ['permission_id' => 3, 'model_type' => 'App\Models\User', 'model_id' => 8],
        ]);

        Artisan::call('authorization:migrate-spatie');

        self::assertSame(['42', '8'], DB::table('auth_authorizable_roles')->orderBy('authorizable_id')->pluck('authorizable_id')->all());
        self::assertSame(['42', '8'], DB::table('auth_authorizable_permissions')->orderBy('authorizable_id')->pluck('authorizable_id')->all());
    }

    /**
     * A dry run reports the names it would refuse and excludes them from the
     * summary counts.
     *
     * @return void
     */
    public function testDryRunReportsRefusedNames(): void
    {
        $this->seedNamesForValidation();

        $exitCode = Artisan::call('authorization:migrate-spatie', ['--dry-run' => true]);
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString(self::refusalLine('role', 'has space'), $output);
        self::assertStringContainsString(self::refusalLine('permission', 'posts?edit'), $output);
        self::assertMatchesRegularExpression('/\|\s+roles\s+\|\s+3\s+\|/', $output);
        self::assertMatchesRegularExpression('/\|\s+permissions\s+\|\s+4\s+\|/', $output);
        self::assertMatchesRegularExpression('/\|\s+role_permissions\s+\|\s+3\s+\|/', $output);
        self::assertMatchesRegularExpression('/\|\s+authorizable_roles\s+\|\s+1\s+\|/', $output);
        self::assertMatchesRegularExpression('/\|\s+authorizable_permissions\s+\|\s+1\s+\|/', $output);
        self::assertSame(0, DB::table('auth_roles')->count());
        self::assertSame(0, DB::table('auth_permissions')->count());
    }

    /**
     * A permission name containing `*` is a wildcard here, so it is reported
     * and skipped with its grants, while a role name containing `*` is compared
     * literally and is migrated.
     *
     * @return void
     */
    public function testWildcardPermissionNamesAreReportedAndSkippedWithTheirGrants(): void
    {
        $this->seedWildcardNames();

        $exitCode = Artisan::call('authorization:migrate-spatie');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString(self::wildcardLine('*'), $output);
        self::assertStringContainsString(self::wildcardLine('posts*'), $output);
        self::assertSame(
            ['admin', 'editor', 'ops.*'],
            DB::table('auth_roles')->pluck('name')->sort()->values()->all(),
        );
        self::assertSame(
            ['posts:create', 'posts:delete', 'posts:edit'],
            DB::table('auth_permissions')->pluck('name')->sort()->values()->all(),
        );
        self::assertSame(2, DB::table('auth_role_permissions')->count());
        self::assertSame(2, DB::table('auth_authorizable_roles')->count());
        self::assertSame(1, DB::table('auth_authorizable_permissions')->count());
    }

    /**
     * A permission the code does not declare is reported and skipped with its
     * grants, on a dry run too, and a stored row of its name is neither reused
     * nor granted.
     *
     * @return void
     */
    public function testUndeclaredPermissionsAreReportedAndSkippedWithTheirGrants(): void
    {
        $this->declarePermissions('posts:create', 'posts:edit');

        $stale = Permission::query()->create(['name' => 'posts:delete', 'guard' => 'web']);
        $line  = 'Skipped: ' . (new UndeclaredPermissionException('posts:delete'))->getMessage() . ' Its grants are not migrated.';

        Artisan::call('authorization:migrate-spatie', ['--dry-run' => true]);

        self::assertStringContainsString($line, Artisan::output());

        $exitCode = Artisan::call('authorization:migrate-spatie');

        self::assertSame(0, $exitCode);
        self::assertStringContainsString($line, Artisan::output());
        self::assertSame(
            ['posts:create', 'posts:delete', 'posts:edit'],
            DB::table('auth_permissions')->pluck('name')->sort()->values()->all(),
        );
        self::assertSame(1, DB::table('auth_role_permissions')->count());
        self::assertFalse(DB::table('auth_role_permissions')->where('permission_id', $stale->id)->exists());
        self::assertSame(1, DB::table('auth_authorizable_permissions')->count());
    }

    /**
     * Return each Spatie table that may hold team ids.
     *
     * @return iterable<string, array{string}>
     */
    public static function teamTables(): iterable
    {
        yield 'roles' => ['roles'];
        yield 'role grants' => ['model_has_roles'];
        yield 'permission grants' => ['model_has_permissions'];
    }

    /**
     * A team id in any of Spatie's team tables stops the import before anything
     * is written, a dry run too, when no tenant type is given.
     *
     * @param  string  $table
     * @return void
     */
    #[DataProvider('teamTables')]
    public function testRefusesTeamIdsWithoutATenantType(string $table): void
    {
        $this->addTeamColumn();

        DB::table($table)->update(['team_id' => 5]);

        foreach ([['--dry-run' => true], []] as $options) {
            self::assertSame(1, Artisan::call('authorization:migrate-spatie', $options));

            $output = Artisan::output();

            self::assertStringContainsString("Spatie table '{$table}' holds team ids in 'team_id'. Pass --team-tenant-type to import them into tenants.", $output);
            self::assertStringNotContainsString('Migration summary', $output);
        }

        self::assertSame(\array_fill_keys(\array_keys(self::targetRows()), []), self::targetRows());
    }

    /**
     * A team column that holds no team id imports every row platform-wide.
     *
     * @return void
     */
    public function testATeamColumnWithNoTeamIdsImportsPlatformWide(): void
    {
        $this->addTeamColumn();

        self::assertSame(0, Artisan::call('authorization:migrate-spatie'));
        self::assertSame(2, DB::table('auth_roles')->whereNull('tenant_type')->whereNull('tenant_id')->count());

        foreach (['auth_authorizable_roles', 'auth_authorizable_permissions'] as $table) {
            self::assertSame(1, DB::table($table)->whereNull('tenant_type')->whereNull('tenant_id')->count(), $table);
        }
    }

    /**
     * With a tenant type, a team's role is owned by the team's tenant and a
     * grant with a team id is made in that tenant; a role with no team id is
     * the platform's, granted in each team that holds it. A dry run and a
     * re-run write nothing.
     *
     * @return void
     */
    public function testImportsTeamRowsIntoTheTeamsTenant(): void
    {
        $this->addTeamColumn();
        $this->seedTeams('team_id');

        $options = ['--team-tenant-type' => 'team'];

        self::assertSame(0, Artisan::call('authorization:migrate-spatie', [...$options, '--dry-run' => true]));
        self::assertSame(0, DB::table('auth_roles')->count());
        self::assertSame(0, Artisan::call('authorization:migrate-spatie', $options));

        self::assertSame(['admin||', 'editor|team|5', 'editor|team|6'], self::teamRoles());
        self::assertSame(['42|admin|team|5', '42|admin|team|6', '43|editor|team|5', '44|editor|team|6'], self::teamGrants('auth_authorizable_roles', 'auth_roles', 'role_id'));
        self::assertSame(['42|posts:edit|team|6'], self::teamGrants('auth_authorizable_permissions', 'auth_permissions', 'permission_id'));
        self::assertSame(['admin|||posts:create', 'admin|||posts:delete', 'editor|team|5|posts:edit', 'editor|team|6|posts:edit'], self::teamRolePermissions());

        $before = self::targetRows();

        self::assertSame(0, Artisan::call('authorization:migrate-spatie', $options));

        $output = Artisan::output();

        self::assertSame($before, self::targetRows());
        self::assertMatchesRegularExpression('/\|\s+roles\s+\|\s+0\s+\|\s+3\s+\|/', $output);
        self::assertMatchesRegularExpression('/\|\s+role_permissions\s+\|\s+0\s+\|\s+4\s+\|/', $output);
        self::assertMatchesRegularExpression('/\|\s+authorizable_roles\s+\|\s+0\s+\|\s+4\s+\|/', $output);
    }

    /**
     * A team grant holds in the team's tenant alone, not the tenants below it,
     * as does a grant of a team's role with no team id, made in the role's
     * tenant.
     *
     * @return void
     */
    public function testTeamGrantsHoldInTheTeamAlone(): void
    {
        $this->app?->instance(TenantTree::class, FakeTenantTree::of([
            [new Reference('team', '5'), null],
            [new Reference('team', '6'), null],
            [new Reference('team', '7'), new Reference('team', '5')],
            [new Reference('team', '8'), new Reference('team', '6')],
        ]));
        $this->addTeamColumn();
        $this->seedTeams('team_id');

        DB::table('model_has_roles')->insert(['role_id' => 2, 'model_type' => 'App\Models\User', 'model_id' => 45, 'team_id' => null]);

        self::assertSame(0, Artisan::call('authorization:migrate-spatie', ['--team-tenant-type' => 'team']));

        /** @var \SineMacula\Laravel\Authorization\Services\GrantScopeQuery $scopes */
        $scopes = app(GrantScopeQuery::class);

        $users = \array_map(static fn (string $id): Reference => new Reference('App\Models\User', $id), ['42', '43', '45']);

        self::assertEquals($users, $scopes->granteesReaching(new Reference('team', '5')));
        self::assertSame([], $scopes->granteesReaching(new Reference('team', '7')));
        self::assertSame([], $scopes->granteesReaching(new Reference('team', '8')));
    }

    /**
     * A team's role granted in another team is refused as the grant service
     * refuses it, on a dry run too.
     *
     * @return void
     */
    public function testRefusesATeamsRoleGrantedInAnotherTeam(): void
    {
        $this->useAnAuthorizationConnection();
        $this->addTeamColumn();
        $this->seedTeams('team_id');

        DB::table('model_has_roles')->insert(['role_id' => 2, 'model_type' => 'App\Models\User', 'model_id' => 45, 'team_id' => 6]);

        foreach ([['--dry-run' => true], []] as $options) {
            $failure = null;

            try {
                Artisan::call('authorization:migrate-spatie', [...$options, '--team-tenant-type' => 'team']);
            } catch (\Throwable $exception) {
                $failure = $exception;
            }

            self::assertInstanceOf(GrantScopeMismatchException::class, $failure);
            self::assertStringContainsString('The role \'editor\' belongs to tenant \'team:5\'', $failure->getMessage());
            self::assertStringEndsWith('not in tenant \'team:6\'.', $failure->getMessage());
            self::assertSame([], self::authorizationConnection()->table('auth_authorizable_roles')->where('authorizable_id', '45')->get()->all());
        }
    }

    /**
     * Without `--team-column`, the import reads Spatie's configured team
     * foreign key, else `team_id` when that is blank.
     *
     * @return void
     */
    public function testDefaultsTheTeamColumnToSpatiesTeamForeignKey(): void
    {
        $this->addTeamColumn('organisation_id');
        $this->seedTeams('organisation_id');

        config()->set('permission.column_names.team_foreign_key', 'organisation_id');

        self::assertSame(1, Artisan::call('authorization:migrate-spatie'));
        self::assertStringContainsString('Spatie table \'roles\' holds team ids in \'organisation_id\'.', Artisan::output());

        config()->set('permission.column_names.team_foreign_key', '');

        self::assertSame(1, Artisan::call('authorization:migrate-spatie', ['--team-tenant-type' => 'organisation']));
        self::assertStringContainsString('No Spatie table has the team column \'team_id\'.', Artisan::output());
    }

    /**
     * `--team-column` names the team column the import reads, in place of
     * Spatie's configured team foreign key.
     *
     * @return void
     */
    public function testReadsTheTeamColumnTheOptionNames(): void
    {
        $this->addTeamColumn('organisation_id');
        $this->seedTeams('organisation_id');

        config()->set('permission.column_names.team_foreign_key', 'team_id');

        self::assertSame(1, Artisan::call('authorization:migrate-spatie', ['--team-column' => 'organisation_id']));
        self::assertStringContainsString('Spatie table \'roles\' holds team ids in \'organisation_id\'.', Artisan::output());
        self::assertSame(0, Artisan::call('authorization:migrate-spatie', ['--team-column' => 'organisation_id', '--team-tenant-type' => 'organisation']));
        self::assertSame(['admin||', 'editor|organisation|5', 'editor|organisation|6'], self::teamRoles());
        self::assertSame(['42|posts:edit|organisation|6'], self::teamGrants('auth_authorizable_permissions', 'auth_permissions', 'permission_id'));
    }

    /**
     * A team role is reused only for the tenant type it was imported under.
     *
     * @return void
     */
    public function testReusesTeamRolesOnlyForTheirTenantType(): void
    {
        $this->addTeamColumn();
        $this->seedTeams('team_id');

        self::assertSame(0, Artisan::call('authorization:migrate-spatie', ['--team-tenant-type' => 'team']));
        self::assertSame(0, Artisan::call('authorization:migrate-spatie', ['--team-tenant-type' => 'organisation']));
        self::assertMatchesRegularExpression('/\|\s+roles\s+\|\s+2\s+\|\s+1\s+\|/', Artisan::output());
        self::assertSame(['admin||', 'editor|organisation|5', 'editor|organisation|6', 'editor|team|5', 'editor|team|6'], self::teamRoles());
    }

    /**
     * A tenant type with a team column no Spatie table has stops the import
     * before anything is written, a dry run too.
     *
     * @return void
     */
    public function testRefusesATenantTypeWhenNoTableHasTheTeamColumn(): void
    {
        foreach ([['--dry-run' => true], []] as $options) {
            self::assertSame(1, Artisan::call('authorization:migrate-spatie', [...$options, '--team-tenant-type' => 'team']));
            self::assertStringContainsString('No Spatie table has the team column \'team_id\'. Pass --team-column to name it.', Artisan::output());
        }

        self::assertSame(\array_fill_keys(\array_keys(self::targetRows()), []), self::targetRows());
    }

    /**
     * A blank tenant type counts as none, so team ids stop the import.
     *
     * @return void
     */
    public function testABlankTenantTypeRefusesTeamIds(): void
    {
        $this->addTeamColumn();
        $this->seedTeams('team_id');

        self::assertSame(1, Artisan::call('authorization:migrate-spatie', ['--team-tenant-type' => '']));
        self::assertStringContainsString('Spatie table \'roles\' holds team ids in \'team_id\'.', Artisan::output());
        self::assertSame(\array_fill_keys(\array_keys(self::targetRows()), []), self::targetRows());
    }

    /**
     * Command fails when Spatie source tables do not exist.
     *
     * @return void
     */
    public function testFailsWhenSpatieTablesDoNotExist(): void
    {
        Schema::drop('model_has_roles');

        $exitCode = Artisan::call('authorization:migrate-spatie');

        self::assertSame(1, $exitCode);
    }

    /**
     * Configure the package to use prefixed target table names so they do not
     * collide with Spatie's source tables.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('authorization.tables.roles', 'auth_roles');
        $config->set('authorization.tables.permissions', 'auth_permissions');
        $config->set('authorization.tables.policies', 'auth_policies');
        $config->set('authorization.tables.role_permissions', 'auth_role_permissions');
        $config->set('authorization.tables.authorizable_roles', 'auth_authorizable_roles');
        $config->set('authorization.tables.authorizable_permissions', 'auth_authorizable_permissions');
        $config->set('authorization.tables.authorizable_policies', 'auth_authorizable_policies');
    }

    /**
     * Return the line the command prints for a refused name.
     *
     * @param  string  $kind
     * @param  string  $name
     * @return string
     */
    private static function refusalLine(string $kind, string $name): string
    {
        return "Skipped: Invalid {$kind} name '{$name}': allowed characters are letters, digits, '_', '-', ':', '.', "
            . 'and \'*\', at most 191 of them. Its grants are not migrated.';
    }

    /**
     * Return the line the command prints for a skipped wildcard permission.
     *
     * @param  string  $name
     * @return string
     */
    private static function wildcardLine(string $name): string
    {
        return "Skipped: permission name '{$name}' contains '*', which is a wildcard here and would grant other "
            . 'permissions. Its grants are not migrated.';
    }

    /**
     * Seed a role and two permissions whose names contain `*`, with grants that
     * reference all three.
     *
     * @return void
     */
    private function seedWildcardNames(): void
    {
        DB::table('roles')->insert([
            ['id' => 3, 'name' => 'ops.*', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);

        DB::table('permissions')->insert([
            ['id' => 4, 'name' => '*', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
            ['id' => 5, 'name' => 'posts*', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);

        DB::table('role_has_permissions')->insert([
            ['permission_id' => 4, 'role_id' => 2],
            ['permission_id' => 5, 'role_id' => 3],
        ]);

        DB::table('model_has_roles')->insert([
            ['role_id' => 3, 'model_type' => 'App\Models\User', 'model_id' => 7],
        ]);

        DB::table('model_has_permissions')->insert([
            ['permission_id' => 4, 'model_type' => 'App\Models\User', 'model_id' => 7],
        ]);
    }

    /**
     * Seed a refused role and permission, each followed by a valid dotted one,
     * with grants that reference all four.
     *
     * @return void
     */
    private function seedNamesForValidation(): void
    {
        DB::table('roles')->insert([
            ['id' => 3, 'name' => 'has space', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
            ['id' => 4, 'name' => 'content.manager', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);

        DB::table('permissions')->insert([
            ['id' => 4, 'name' => 'posts?edit', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
            ['id' => 5, 'name' => 'posts.publish', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);

        DB::table('role_has_permissions')->insert([
            ['permission_id' => 4, 'role_id' => 1],
            ['permission_id' => 1, 'role_id' => 3],
            ['permission_id' => 5, 'role_id' => 4],
        ]);

        DB::table('model_has_roles')->insert([
            ['role_id' => 3, 'model_type' => 'App\Models\User', 'model_id' => 7],
        ]);

        DB::table('model_has_permissions')->insert([
            ['permission_id' => 4, 'model_type' => 'App\Models\User', 'model_id' => 7],
        ]);
    }

    /**
     * Replace the Spatie tables with string-keyed ones, as on a Spatie install
     * that uses UUIDs, and seed one role, one permission and a grant of each
     * kind.
     *
     * @return void
     */
    private function recreateSpatieTablesWithStringIds(): void
    {
        foreach (['model_has_permissions', 'model_has_roles', 'role_has_permissions', 'permissions', 'roles'] as $table) {
            Schema::drop($table);
        }

        foreach (['roles', 'permissions'] as $table) {
            Schema::create($table, static function (Blueprint $blueprint): void {
                $blueprint->uuid('id')->primary();
                $blueprint->string('name');
                $blueprint->string('guard_name');
                $blueprint->timestamps();
            });
        }

        Schema::create('role_has_permissions', static function (Blueprint $table): void {
            $table->uuid('permission_id');
            $table->uuid('role_id');
        });

        foreach (['model_has_roles' => 'role_id', 'model_has_permissions' => 'permission_id'] as $table => $column) {
            Schema::create($table, static function (Blueprint $blueprint) use ($column): void {
                $blueprint->uuid($column);
                $blueprint->string('model_type');
                $blueprint->unsignedBigInteger('model_id');
            });
        }

        DB::table('roles')->insert([
            'id'         => self::STRING_ROLE_ID,
            'name'       => 'admin',
            'guard_name' => 'web',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('permissions')->insert([
            'id'         => self::STRING_PERMISSION_ID,
            'name'       => 'posts:edit',
            'guard_name' => 'web',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('role_has_permissions')->insert([
            'permission_id' => self::STRING_PERMISSION_ID,
            'role_id'       => self::STRING_ROLE_ID,
        ]);

        DB::table('model_has_roles')->insert([
            'role_id'    => self::STRING_ROLE_ID,
            'model_type' => 'App\Models\User',
            'model_id'   => 42,
        ]);

        DB::table('model_has_permissions')->insert([
            'permission_id' => self::STRING_PERMISSION_ID,
            'model_type'    => 'App\Models\User',
            'model_id'      => 42,
        ]);
    }

    /**
     * Add a nullable team column to Spatie's roles and grant tables.
     *
     * @param  string  $column
     * @return void
     */
    private function addTeamColumn(string $column = 'team_id'): void
    {
        foreach (['roles', 'model_has_roles', 'model_has_permissions'] as $table) {
            Schema::table($table, static function (Blueprint $blueprint) use ($column): void {
                $blueprint->unsignedBigInteger($column)->nullable();
            });
        }
    }

    /**
     * Make Spatie's `editor` role team 5's, add a second `editor` for team 6,
     * give each `posts:edit` and grant roles and a permission in both teams.
     *
     * @param  string  $column
     * @return void
     */
    private function seedTeams(string $column): void
    {
        DB::table('roles')->where('id', 2)->update([$column => 5]);
        DB::table('roles')->insert(['id' => 3, 'name' => 'editor', 'guard_name' => 'web', $column => 6, 'created_at' => now(), 'updated_at' => now()]);
        DB::table('role_has_permissions')->insert([['permission_id' => 2, 'role_id' => 2], ['permission_id' => 2, 'role_id' => 3]]);
        DB::table('model_has_roles')->update([$column => 5]);
        DB::table('model_has_roles')->insert([
            ['role_id' => 1, 'model_type' => 'App\Models\User', 'model_id' => 42, $column => 6],
            ['role_id' => 2, 'model_type' => 'App\Models\User', 'model_id' => 43, $column => 5],
            ['role_id' => 3, 'model_type' => 'App\Models\User', 'model_id' => 44, $column => 6],
        ]);
        DB::table('model_has_permissions')->update([$column => 6]);
    }

    /**
     * Return each imported role as its name and owner, in a stable order.
     *
     * @return list<string>
     */
    private static function teamRoles(): array
    {
        return \array_values(DB::table('auth_roles')->get()->map(static fn (object $row): string => "{$row->name}|{$row->tenant_type}|{$row->tenant_id}")->sort()->all());
    }

    /**
     * Return each imported role permission as the role's name and owner and the
     * permission's name, in a stable order.
     *
     * @return list<string>
     */
    private static function teamRolePermissions(): array
    {
        $rows = DB::table('auth_role_permissions')
            ->join('auth_roles', 'auth_roles.id', '=', 'auth_role_permissions.role_id')
            ->join('auth_permissions', 'auth_permissions.id', '=', 'auth_role_permissions.permission_id')
            ->get(['auth_roles.name as role', 'auth_roles.tenant_type', 'auth_roles.tenant_id', 'auth_permissions.name as permission']);

        return \array_values($rows->map(static fn (object $row): string => "{$row->role}|{$row->tenant_type}|{$row->tenant_id}|{$row->permission}")->sort()->all());
    }

    /**
     * Return each grant in the table as its grantee, the name it grants and its
     * tenant, in a stable order.
     *
     * @param  string  $grants
     * @param  string  $targets
     * @param  string  $column
     * @return list<string>
     */
    private static function teamGrants(string $grants, string $targets, string $column): array
    {
        $rows = DB::table($grants)
            ->join($targets, "{$targets}.id", '=', "{$grants}.{$column}")
            ->get(["{$grants}.authorizable_id", "{$targets}.name", "{$grants}.tenant_type", "{$grants}.tenant_id"]);

        return \array_values($rows->map(static fn (object $row): string => "{$row->authorizable_id}|{$row->name}|{$row->tenant_type}|{$row->tenant_id}")->sort()->all());
    }

    /**
     * Return every row of the package's target tables, in a stable order.
     *
     * @return array<string, array<int, string>>
     */
    private static function targetRows(): array
    {
        $rows = [];

        foreach (['auth_roles', 'auth_permissions', 'auth_role_permissions', 'auth_authorizable_roles', 'auth_authorizable_permissions'] as $table) {
            $rows[$table] = DB::table($table)->get()->map(static fn (object $row): string => (string) \json_encode($row))->sort()->values()->all();
        }

        return $rows;
    }

    /**
     * Create Spatie's tables with auto-increment IDs, under Spatie's default
     * names unless others are given.
     *
     * @param  \Illuminate\Database\Schema\Builder|null  $schema
     * @param  array<string, string>  $names
     * @return void
     */
    private function createSpatieTables(?SchemaBuilder $schema = null, array $names = []): void
    {
        $schema ??= DB::connection()->getSchemaBuilder();
        $name = static fn (string $table): string => $names[$table] ?? $table;

        foreach (['roles', 'permissions'] as $table) {
            $schema->create($name($table), static function (Blueprint $blueprint): void {
                $blueprint->increments('id');
                $blueprint->string('name');
                $blueprint->string('guard_name');
                $blueprint->timestamps();
            });
        }

        $schema->create($name('role_has_permissions'), static function (Blueprint $table): void {
            $table->unsignedInteger('permission_id');
            $table->unsignedInteger('role_id');
            $table->primary(['permission_id', 'role_id']);
        });

        foreach (['model_has_roles' => 'role_id', 'model_has_permissions' => 'permission_id'] as $table => $column) {
            $schema->create($name($table), static function (Blueprint $blueprint) use ($column): void {
                $blueprint->unsignedInteger($column);
                $blueprint->string('model_type');
                $blueprint->unsignedBigInteger('model_id');
                $blueprint->index(['model_id', 'model_type']);
            });
        }
    }

    /**
     * Seed sample Spatie data for migration testing.
     *
     * @return void
     */
    private function seedSpatieData(): void
    {
        DB::table('roles')->insert([
            ['id' => 1, 'name' => 'admin', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
            ['id' => 2, 'name' => 'editor', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);

        DB::table('permissions')->insert([
            ['id' => 1, 'name' => 'posts:create', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
            ['id' => 2, 'name' => 'posts:edit', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
            ['id' => 3, 'name' => 'posts:delete', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);

        DB::table('role_has_permissions')->insert([
            ['permission_id' => 1, 'role_id' => 1],
            ['permission_id' => 3, 'role_id' => 1],
        ]);

        DB::table('model_has_roles')->insert([
            ['role_id' => 1, 'model_type' => 'App\Models\User', 'model_id' => 42],
        ]);

        DB::table('model_has_permissions')->insert([
            ['permission_id' => 2, 'model_type' => 'App\Models\User', 'model_id' => 42],
        ]);
    }
}
