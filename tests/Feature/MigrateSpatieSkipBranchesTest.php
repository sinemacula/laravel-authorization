<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\MigrateSpatieCommand;
use Tests\TestCase;

/**
 * Coverage-focused feature tests for the skip branches in
 * `MigrateSpatieCommand` — unmapped role, permission, and policy
 * references plus the missing-target-table failure path.
 *
 * Package target tables are configured to the `auth_` prefix at
 * environment-definition time so the Spatie source names
 * (`roles`, `permissions`, ...) are free for the source schema
 * created inside `setUp()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MigrateSpatieCommand::class)]
final class MigrateSpatieSkipBranchesTest extends TestCase
{
    /**
     * Seed the Spatie source schema. The package target schema
     * (`auth_`-prefixed) is migrated by the Testbench bootstrap.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        foreach (['model_has_permissions', 'model_has_roles', 'role_has_permissions', 'permissions', 'roles'] as $table) {
            Schema::dropIfExists($table);
        }

        parent::tearDown();
    }

    protected function setUp(): void
    {
        parent::setUp();

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
        Schema::create('role_has_permissions', static function (Blueprint $table): void {
            $table->unsignedInteger('permission_id');
            $table->unsignedInteger('role_id');
            $table->primary(['permission_id', 'role_id']);
        });
        Schema::create('model_has_roles', static function (Blueprint $table): void {
            $table->unsignedInteger('role_id');
            $table->string('model_type');
            $table->unsignedBigInteger('model_id');
        });
        Schema::create('model_has_permissions', static function (Blueprint $table): void {
            $table->unsignedInteger('permission_id');
            $table->string('model_type');
            $table->unsignedBigInteger('model_id');
        });
    }

    /**
     * `verifyTargetSchema()` fails when a target table is missing.
     * Targets lines 70, 167, 169 of `MigrateSpatieCommand`.
     *
     * The previously-migrated `auth_authorizable_roles` table is
     * dropped so the command's schema probe fails without
     * poisoning the test-tier migrator (rewriting the config at
     * this point would have it roll back tables under the wrong
     * name on teardown).
     *
     * @return void
     */
    public function testFailsWhenTargetTableMissing(): void
    {
        Schema::drop('auth_authorizable_roles');

        $exitCode = Artisan::call('authorization:migrate-spatie');
        $output   = Artisan::output();

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Target table \'auth_authorizable_roles\' does not exist', $output);

        // Restore the target table so teardown's migrator can roll back.
        Schema::create('auth_authorizable_roles', static function (Blueprint $table): void {
            $table->string('authorizable_type');
            $table->string('authorizable_id');
            $table->string('role_id');
            $table->timestamp('expires_at')->nullable();
        });
    }

    /**
     * Unmapped rows in `role_has_permissions` are skipped without
     * aborting the migration. Targets line 279 of
     * `MigrateSpatieCommand`.
     *
     * @return void
     */
    public function testSkipsUnmappedRolePermissionRows(): void
    {
        DB::table('roles')->insert([
            ['id' => 1, 'name' => 'admin', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
            ['id' => 2, 'name' => 'editor', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);
        DB::table('permissions')->insert([
            ['id' => 1, 'name' => 'a:do', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
            ['id' => 2, 'name' => 'b:do', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);

        // Unmappable rows interleaved before *and* after mappable
        // rows — a `break` mutation would stop processing after
        // the first unmappable row and miss the later mappable
        // one, distinguishing it from the real `continue`.
        DB::table('role_has_permissions')->insert([
            ['permission_id' => 999, 'role_id' => 1],    // unmappable permission
            ['permission_id' => 1, 'role_id' => 1],      // mappable
            ['permission_id' => 1, 'role_id' => 999],    // unmappable role
            ['permission_id' => 2, 'role_id' => 2],      // mappable
        ]);

        $exitCode = Artisan::call('authorization:migrate-spatie');

        self::assertSame(0, $exitCode);
        self::assertSame(2, DB::table('auth_role_permissions')->count());
    }

    /**
     * Unmapped rows in `model_has_roles` are skipped. Targets
     * line 314.
     *
     * @return void
     */
    public function testSkipsUnmappedModelRoleRows(): void
    {
        DB::table('roles')->insert([
            ['id' => 1, 'name' => 'admin', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
            ['id' => 2, 'name' => 'editor', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);

        // Unmappable row before a mappable one so a `break`
        // mutation would skip the mappable row.
        DB::table('model_has_roles')->insert([
            ['role_id' => 999, 'model_type' => 'App\User', 'model_id' => 7],
            ['role_id' => 1, 'model_type' => 'App\User', 'model_id' => 8],
            ['role_id' => 2, 'model_type' => 'App\User', 'model_id' => 9],
        ]);

        Artisan::call('authorization:migrate-spatie');

        self::assertSame(2, DB::table('auth_authorizable_roles')->count());
    }

    /**
     * Unmapped rows in `model_has_permissions` are skipped.
     * Targets line 350.
     *
     * @return void
     */
    public function testSkipsUnmappedModelPermissionRows(): void
    {
        DB::table('permissions')->insert([
            ['id' => 1, 'name' => 'a:do', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
            ['id' => 2, 'name' => 'b:do', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);

        // Unmappable row before a mappable one so a `break`
        // mutation would skip the mappable row.
        DB::table('model_has_permissions')->insert([
            ['permission_id' => 999, 'model_type' => 'App\User', 'model_id' => 7],
            ['permission_id' => 1, 'model_type' => 'App\User', 'model_id' => 8],
            ['permission_id' => 2, 'model_type' => 'App\User', 'model_id' => 9],
        ]);

        Artisan::call('authorization:migrate-spatie');

        self::assertSame(2, DB::table('auth_authorizable_permissions')->count());
    }

    /**
     * The summary table output reflects zero counts when every
     * Spatie table is empty — pins the counter initialisation
     * against IncrementInteger / DecrementInteger mutations on
     * the `=> 0` seeds.
     *
     * @return void
     */
    public function testSummaryReportsZeroCountsWhenSpatieSourceIsEmpty(): void
    {
        $exitCode = Artisan::call('authorization:migrate-spatie');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);

        // The migration summary table is rendered with each row
        // `[table, count]`. An initial value other than 0 would
        // surface as a non-zero count for the otherwise-empty
        // source schema.
        self::assertStringContainsString('Migration summary', $output);
        self::assertMatchesRegularExpression('/roles\s+\|\s+0\s+/', $output);
        self::assertMatchesRegularExpression('/permissions\s+\|\s+0\s+/', $output);
        self::assertMatchesRegularExpression('/role_permissions\s+\|\s+0\s+/', $output);
        self::assertMatchesRegularExpression('/authorizable_roles\s+\|\s+0\s+/', $output);
        self::assertMatchesRegularExpression('/authorizable_permissions\s+\|\s+0\s+/', $output);
    }

    /**
     * The summary table output with seeded rows reports exact
     * counts — pins the counter increment (`$counts['roles']++`)
     * against Increment / Decrement / UnwrapPostInc mutations.
     *
     * @return void
     */
    public function testSummaryReportsExactCountsForEachTable(): void
    {
        DB::table('roles')->insert([
            ['id' => 1, 'name' => 'admin', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
            ['id' => 2, 'name' => 'editor', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
            ['id' => 3, 'name' => 'viewer', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);
        DB::table('permissions')->insert([
            ['id' => 1, 'name' => 'a:do', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
            ['id' => 2, 'name' => 'b:do', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);
        DB::table('role_has_permissions')->insert([
            ['permission_id' => 1, 'role_id' => 1],
        ]);
        DB::table('model_has_roles')->insert([
            ['role_id' => 1, 'model_type' => 'App\User', 'model_id' => 7],
            ['role_id' => 2, 'model_type' => 'App\User', 'model_id' => 8],
        ]);
        DB::table('model_has_permissions')->insert([
            ['permission_id' => 1, 'model_type' => 'App\User', 'model_id' => 9],
        ]);

        Artisan::call('authorization:migrate-spatie');
        $output = Artisan::output();

        self::assertMatchesRegularExpression('/roles\s+\|\s+3\s+/', $output);
        self::assertMatchesRegularExpression('/permissions\s+\|\s+2\s+/', $output);
        self::assertMatchesRegularExpression('/role_permissions\s+\|\s+1\s+/', $output);
        self::assertMatchesRegularExpression('/authorizable_roles\s+\|\s+2\s+/', $output);
        self::assertMatchesRegularExpression('/authorizable_permissions\s+\|\s+1\s+/', $output);
    }

    /**
     * Dry run renders the "No data was written" warning message —
     * pins the dry-run banner against ConcatOperandRemoval and
     * string-message mutations.
     *
     * @return void
     */
    public function testDryRunRendersWarningAndDoesNotWrite(): void
    {
        DB::table('roles')->insert([
            ['id' => 1, 'name' => 'admin', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);

        Artisan::call('authorization:migrate-spatie', ['--dry-run' => true]);
        $output = Artisan::output();

        self::assertStringContainsString('Dry run — no data will be written.', $output);
        self::assertStringContainsString('Re-run without --dry-run to apply.', $output);
        self::assertSame(0, DB::table('auth_roles')->count(), 'Dry run must not persist any row.');
    }

    /**
     * The command coerces the `--dry-run` option to bool so an
     * integer-shaped "0" still writes. Pins the (bool) cast
     * against CastBool mutation.
     *
     * @return void
     */
    public function testDryRunFalseWithFalsyOptionPerformsRealMigration(): void
    {
        DB::table('roles')->insert([
            ['id' => 1, 'name' => 'admin', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);

        Artisan::call('authorization:migrate-spatie');

        self::assertSame(1, DB::table('auth_roles')->count(), 'Default (no --dry-run) should write to the target.');
    }

    /**
     * Configure the package to use prefixed target table names so they
     * do not collide with Spatie's source tables.
     *
     * @param  mixed  $app
     * @return void
     */
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var ConfigRepository $config */
        $config = app(ConfigRepository::class);

        $config->set('authorization.tables.roles', 'auth_roles');
        $config->set('authorization.tables.permissions', 'auth_permissions');
        $config->set('authorization.tables.policies', 'auth_policies');
        $config->set('authorization.tables.role_permissions', 'auth_role_permissions');
        $config->set('authorization.tables.authorizable_roles', 'auth_authorizable_roles');
        $config->set('authorization.tables.authorizable_permissions', 'auth_authorizable_permissions');
        $config->set('authorization.tables.authorizable_policies', 'auth_authorizable_policies');
    }
}
