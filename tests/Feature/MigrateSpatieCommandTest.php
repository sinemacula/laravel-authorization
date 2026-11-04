<?php

declare(strict_types = 1);

namespace Tests\Feature;

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

        $roleIds = DB::table('auth_roles')->pluck('id')->all();

        foreach ($roleIds as $id) {
            self::assertIsString($id);
            self::assertMatchesRegularExpression(
                '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',
                $id,
            );
        }
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
        self::assertSame(0, DB::table('auth_roles')->count());
        self::assertSame(0, DB::table('auth_permissions')->count());
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
            . 'and \'*\'. Its grants are not migrated.';
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
     * Create Spatie's default tables with auto-increment IDs.
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
