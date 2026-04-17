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
     * The dry-run banner info message is rendered. Pins the
     * MethodCallRemoval mutant on line 78.
     *
     * @return void
     */
    public function testDryRunInfoBannerIsRendered(): void
    {
        Artisan::call('authorization:migrate-spatie', ['--dry-run' => true]);
        $output = Artisan::output();

        self::assertStringContainsString('Dry run', $output);
    }

    /**
     * The summary table headers include both "Target Table" and
     * "Rows". Pins the ArrayItemRemoval mutant on line 113.
     *
     * @return void
     */
    public function testSummaryTableIncludesBothHeaders(): void
    {
        Artisan::call('authorization:migrate-spatie');
        $output = Artisan::output();

        self::assertStringContainsString('Target Table', $output);
        self::assertStringContainsString('Rows', $output);
    }

    /**
     * Dry-run mode calls the callback directly (no transaction)
     * and still reports counts. Pins the IfNegation on line 104
     * and the FunctionCallRemoval on line 105.
     *
     * @return void
     */
    public function testDryRunExecutesCallbackAndReportsCounts(): void
    {
        DB::table('roles')->insert([
            ['id' => 1, 'name' => 'dry-admin', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);

        Artisan::call('authorization:migrate-spatie', ['--dry-run' => true]);
        $output = Artisan::output();

        // The count should be 1 (callback ran), but no data written.
        self::assertMatchesRegularExpression('/roles\s+\|\s+1\s+/', $output);
        self::assertSame(0, DB::table('auth_roles')->count());
    }

    /**
     * `verifySourceSchema` outputs the missing table name. Pins the
     * MethodCallRemoval mutant on line 138.
     *
     * @return void
     */
    public function testMissingSourceTableErrorIncludesTableName(): void
    {
        Schema::drop('model_has_permissions');

        Artisan::call('authorization:migrate-spatie');
        $output = Artisan::output();

        self::assertStringContainsString('model_has_permissions', $output);

        // Restore for teardown.
        Schema::create('model_has_permissions', static function (\Illuminate\Database\Schema\Blueprint $table): void {
            $table->unsignedInteger('permission_id');
            $table->string('model_type');
            $table->unsignedBigInteger('model_id');
        });
    }

    /**
     * The `(string) $count` cast on line 115 is pinned by
     * verifying table rows display as string numbers.
     *
     * @return void
     */
    public function testSummaryCountsAreStringified(): void
    {
        DB::table('roles')->insert([
            ['id' => 1, 'name' => 'a', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);

        Artisan::call('authorization:migrate-spatie');
        $output = Artisan::output();

        // The count "1" must appear for roles.
        self::assertMatchesRegularExpression('/roles\s+\|\s+1\s+/', $output);
    }

    /**
     * Roles with integer IDs get converted to UUID strings. Pins
     * the CastString on `(string) Str::orderedUuid()` on line 196.
     *
     * @return void
     */
    public function testIntegerIdIsConvertedToUuidString(): void
    {
        DB::table('roles')->insert([
            ['id' => 1, 'name' => 'int-id-role', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);

        Artisan::call('authorization:migrate-spatie');

        $id = DB::table('auth_roles')->where('name', 'int-id-role')->value('id');
        self::assertIsString($id);
        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',
            $id,
        );
    }

    /**
     * Null timestamps in source data are replaced with `now()`.
     * Pins the Coalesce mutants on lines 205-206 and 245-246.
     *
     * @return void
     */
    public function testNullTimestampsDefaultToNow(): void
    {
        // Insert via raw SQL to get null timestamps.
        DB::table('roles')->insert([
            ['id' => 1, 'name' => 'null-ts', 'guard_name' => 'web', 'created_at' => null, 'updated_at' => null],
        ]);

        Artisan::call('authorization:migrate-spatie');

        $row = DB::table('auth_roles')->where('name', 'null-ts')->first();
        self::assertNotNull($row);
        self::assertNotNull($row->created_at);
        self::assertNotNull($row->updated_at);
    }

    /**
     * The `(string) $data['model_id']` cast on lines 320 and 356
     * is pinned by verifying integer model IDs are stored as
     * strings in the authorizable_id column.
     *
     * @return void
     */
    public function testModelIdIsCastToString(): void
    {
        DB::table('roles')->insert([
            ['id' => 1, 'name' => 'r', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);
        DB::table('permissions')->insert([
            ['id' => 1, 'name' => 'p', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);
        DB::table('model_has_roles')->insert([
            ['role_id' => 1, 'model_type' => 'App\M', 'model_id' => 123],
        ]);
        DB::table('model_has_permissions')->insert([
            ['permission_id' => 1, 'model_type' => 'App\M', 'model_id' => 456],
        ]);

        Artisan::call('authorization:migrate-spatie');

        $roleRow = DB::table('auth_authorizable_roles')->first();
        self::assertNotNull($roleRow);
        self::assertSame('123', $roleRow->authorizable_id);

        $permRow = DB::table('auth_authorizable_permissions')->first();
        self::assertNotNull($permRow);
        self::assertSame('456', $permRow->authorizable_id);
    }

    /**
     * The summary table lists all five target tables. Pins the
     * ArrayItemRemoval mutant on line 154 of `verifyTargetSchema`
     * (which would drop one table check from the config loop).
     *
     * @return void
     */
    public function testSummaryListsAllFiveTargetTables(): void
    {
        Artisan::call('authorization:migrate-spatie');
        $output = Artisan::output();

        self::assertStringContainsString('roles', $output);
        self::assertStringContainsString('permissions', $output);
        self::assertStringContainsString('role_permissions', $output);
        self::assertStringContainsString('authorizable_roles', $output);
        self::assertStringContainsString('authorizable_permissions', $output);
    }

    /**
     * Non-dry-run uses a transaction. Pins the `DB::transaction()`
     * on line 107 (MethodCallRemoval on line 110 for `$this->line`).
     *
     * @return void
     */
    public function testNonDryRunWritesToTarget(): void
    {
        DB::table('roles')->insert([
            ['id' => 1, 'name' => 'txn-role', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);

        Artisan::call('authorization:migrate-spatie');

        self::assertSame(1, DB::table('auth_roles')->count());
    }

    /**
     * Null guard_name passes through as null. Pins the Coalesce
     * mutants on `$data['guard_name'] ?? null`.
     *
     * @return void
     */
    public function testNullGuardNamePassesThrough(): void
    {
        DB::table('roles')->insert([
            ['id' => 1, 'name' => 'null-guard', 'guard_name' => 'web', 'created_at' => now(), 'updated_at' => now()],
        ]);

        Artisan::call('authorization:migrate-spatie');

        $row = DB::table('auth_roles')->where('name', 'null-guard')->first();
        self::assertNotNull($row);
        self::assertSame('web', $row->guard_name);
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
}
