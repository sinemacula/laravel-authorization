<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabaseState;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\MigrateSpatieCommand;
use Tests\TestCase;

/**
 * End-to-end integration coverage for the `authorization:migrate-spatie`
 * Artisan command.
 *
 * Creates Spatie's default schema inline, seeds representative rows across all
 * five source tables, and asserts each target table receives the correct row
 * count, UUID rewrites, and morph-column mappings after the command runs.
 * Unlike the Feature-level smoke test, this suite exercises the whole pipeline
 * end-to-end against the shipped migrations (via the in-memory SQLite
 * connection) and asserts each migration invariant individually.
 *
 * The package's target tables are renamed with an `auth_` prefix so they do not
 * collide with Spatie's default `roles` / `permissions` source-table names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(MigrateSpatieCommand::class)]
final class SpatieMigrationTest extends TestCase
{
    /** Name of the Artisan command under test. */
    private const string MIGRATION_COMMAND = 'authorization:migrate-spatie';

    /** Morph-type string seeded into Spatie's model_* tables. */
    private const string MODEL_TYPE = 'App\Models\User';

    /**
     * Build the inline Spatie schema and seed representative data.
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
     * persistent-connection drivers (MySQL / Postgres).
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
     * Roles migrate from Spatie's auto-increment table into the package's
     * UUID-keyed `auth_roles` table.
     *
     * @return void
     */
    public function testRolesMigrateWithGeneratedUuids(): void
    {
        $exitCode = Artisan::call(self::MIGRATION_COMMAND);

        self::assertSame(0, $exitCode);
        self::assertSame(2, DB::table('auth_roles')->count());

        /** @var array<int, string> $ids */
        $ids = DB::table('auth_roles')->pluck('id')->all();

        foreach ($ids as $id) {
            self::assertIsString($id);
            self::assertMatchesRegularExpression(
                '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',
                $id,
                'Expected a UUID to replace the Spatie auto-increment role id.',
            );
        }
    }

    /**
     * Permissions migrate from Spatie's auto-increment table into the package's
     * UUID-keyed `auth_permissions` table.
     *
     * @return void
     */
    public function testPermissionsMigrateWithGeneratedUuids(): void
    {
        $exitCode = Artisan::call(self::MIGRATION_COMMAND);

        self::assertSame(0, $exitCode);
        self::assertSame(3, DB::table('auth_permissions')->count());

        /** @var array<int, string> $ids */
        $ids = DB::table('auth_permissions')->pluck('id')->all();

        foreach ($ids as $id) {
            self::assertIsString($id);
            self::assertMatchesRegularExpression(
                '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',
                $id,
                'Expected a UUID to replace the Spatie auto-increment permission id.',
            );
        }
    }

    /**
     * `model_has_roles` maps into `auth_authorizable_roles` with the morph
     * columns preserved and the role FK rewritten to the corresponding UUID.
     *
     * @return void
     */
    public function testModelHasRolesMapsToAuthorizableRolesWithMorphicColumns(): void
    {
        Artisan::call(self::MIGRATION_COMMAND);

        self::assertSame(1, DB::table('auth_authorizable_roles')->count());

        $row = DB::table('auth_authorizable_roles')->first();
        self::assertNotNull($row);
        self::assertSame(self::MODEL_TYPE, $row->authorizable_type);
        self::assertSame('42', (string) $row->authorizable_id);

        $adminUuid = DB::table('auth_roles')->where('name', 'admin')->value('id');

        self::assertIsString($adminUuid);
        self::assertSame($adminUuid, $row->role_id);
    }

    /**
     * `model_has_permissions` maps into `auth_authorizable_permissions` with
     * the morph columns preserved and the permission FK rewritten to the
     * corresponding UUID.
     *
     * @return void
     */
    public function testModelHasPermissionsMapsToAuthorizablePermissions(): void
    {
        Artisan::call(self::MIGRATION_COMMAND);

        self::assertSame(1, DB::table('auth_authorizable_permissions')->count());

        $row = DB::table('auth_authorizable_permissions')->first();
        self::assertNotNull($row);
        self::assertSame(self::MODEL_TYPE, $row->authorizable_type);
        self::assertSame('42', (string) $row->authorizable_id);

        $editUuid = DB::table('auth_permissions')->where('name', 'posts:edit')->value('id');

        self::assertIsString($editUuid);
        self::assertSame($editUuid, $row->permission_id);
    }

    /**
     * `role_has_permissions` maps into `auth_role_permissions` with both FK
     * columns rewritten to UUIDs that match the migrated role/permission rows.
     *
     * @return void
     */
    public function testRoleHasPermissionsMapsToRolePermissions(): void
    {
        Artisan::call(self::MIGRATION_COMMAND);

        self::assertSame(2, DB::table('auth_role_permissions')->count());

        $adminUuid = DB::table('auth_roles')->where('name', 'admin')->value('id');
        self::assertIsString($adminUuid);

        $permissionUuids = DB::table('auth_role_permissions')
            ->where('role_id', $adminUuid)
            ->pluck('permission_id')
            ->all();

        $permissionNames = DB::table('auth_permissions')
            ->whereIn('id', $permissionUuids)
            ->pluck('name')
            ->sort()
            ->values()
            ->all();

        self::assertSame(['posts:create', 'posts:delete'], $permissionNames);
    }

    /**
     * `--dry-run` reports counts in the summary table without writing any rows
     * to the target tables.
     *
     * @return void
     */
    public function testDryRunReportsCountsWithoutWriting(): void
    {
        $exitCode = Artisan::call(self::MIGRATION_COMMAND, ['--dry-run' => true]);
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
     * Point the package at prefixed table names so the target tables do not
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
     * Create Spatie's default tables with auto-increment integer IDs.
     *
     * @return void
     */
    private function createSpatieTables(): void
    {
        $this->createSpatieAuthorityTables();
        $this->createSpatiePivotTables();
    }

    /**
     * Create the Spatie role and permission master tables.
     *
     * @return void
     */
    private function createSpatieAuthorityTables(): void
    {
        Schema::create('roles', static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('name');
            $table->string('guard_name');
            $table->timestamps();
        });

        Schema::create('permissions', static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('name');
            $table->string('guard_name');
            $table->timestamps();
        });
    }

    /**
     * Create the Spatie pivot tables (role / model junctions).
     *
     * @return void
     */
    private function createSpatiePivotTables(): void
    {
        Schema::create('role_has_permissions', static function (Blueprint $table): void {
            $table->unsignedInteger('permission_id');
            $table->unsignedInteger('role_id');
            $table->primary(['permission_id', 'role_id']);
        });

        Schema::create('model_has_roles', static function (Blueprint $table): void {
            $table->unsignedInteger('role_id');
            $table->string('model_type');
            $table->unsignedBigInteger('model_id');
            $table->index(['model_id', 'model_type']);
        });

        Schema::create('model_has_permissions', static function (Blueprint $table): void {
            $table->unsignedInteger('permission_id');
            $table->string('model_type');
            $table->unsignedBigInteger('model_id');
            $table->index(['model_id', 'model_type']);
        });
    }

    /**
     * Seed representative rows across all five Spatie tables.
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
            ['role_id' => 1, 'model_type' => self::MODEL_TYPE, 'model_id' => 42],
        ]);

        DB::table('model_has_permissions')->insert([
            ['permission_id' => 2, 'model_type' => self::MODEL_TYPE, 'model_id' => 42],
        ]);
    }
}
