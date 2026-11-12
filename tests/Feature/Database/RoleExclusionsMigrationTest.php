<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Authorization\Database\MigrationCollisionException;
use Tests\Concerns\CatchesRefusals;
use Tests\TestCase;

/**
 * Feature tests for the migration creating the table of pairs of mutually
 * exclusive roles (AUTHZ-11.8, N135), on the tables configured under custom
 * names, on every database: its columns and indexes, one row a pair, the pairs
 * of a role deleted with it, the collision guard, and a clean drop.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class RoleExclusionsMigrationTest extends TestCase
{
    use CatchesRefusals;

    /** @var string The custom name of the roles table. */
    private const string ROLES = 're_roles';

    /** @var string The custom name of the role exclusions table. */
    private const string EXCLUSIONS = 're_role_exclusions';

    /** @var string The migration creating the roles table. */
    private const string CREATE_ROLES = '2026_04_14_000001_create_roles_table';

    /** @var string The migration under test. */
    private const string CREATE_EXCLUSIONS = '2026_11_12_000001_create_role_exclusions_table';

    /**
     * Point the package at custom table names and create those tables beside
     * the ones the test process migrated once under the default names, so the
     * shared schema of a parallel worker is never changed.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('authorization.tables.roles', self::ROLES);
        $config->set('authorization.tables.role_exclusions', self::EXCLUSIONS);

        self::runMigration(self::CREATE_ROLES, 'up');
        self::runMigration(self::CREATE_EXCLUSIONS, 'up');
    }

    /**
     * Drop the custom tables again, the pairs first, so a database whose schema
     * changes are not rolled back with the test's transaction, as MySQL's are
     * not, is left as it was found.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::runMigration(self::CREATE_EXCLUSIONS, 'down');
        self::runMigration(self::CREATE_ROLES, 'down');

        parent::tearDown();
    }

    /**
     * The table names the pair, its owner, who declared it and when, and is
     * indexed on the second role and on the owner.
     *
     * @return void
     */
    public function testTheTableHoldsThePairItsOwnerAndItsAuthor(): void
    {
        $columns = ['role_id', 'excluded_role_id', 'tenant_type', 'tenant_id', 'granted_by_type', 'granted_by_id', 'created_at', 'updated_at'];

        self::assertTrue(Schema::hasColumns(self::EXCLUSIONS, $columns));
        self::assertTrue(Schema::hasIndex(self::EXCLUSIONS, ['excluded_role_id']));
        self::assertTrue(Schema::hasIndex(self::EXCLUSIONS, ['tenant_type', 'tenant_id']));
        self::assertTrue(Schema::hasIndex(self::EXCLUSIONS, ['role_id', 'excluded_role_id'], 'primary'));
    }

    /**
     * A pair is stored once, and a role deleted takes its pairs with it.
     *
     * @return void
     */
    public function testAPairIsOneRowAndGoesWithItsRoles(): void
    {
        [$first, $second, $third] = [self::role('one'), self::role('two'), self::role('three')];

        $pair = ['role_id' => $first, 'excluded_role_id' => $second];

        DB::table(self::EXCLUSIONS)->insert($pair);
        DB::table(self::EXCLUSIONS)->insertOrIgnore($pair);
        DB::table(self::EXCLUSIONS)->insert(['role_id' => $first, 'excluded_role_id' => $third]);

        self::assertSame(2, DB::table(self::EXCLUSIONS)->count());

        DB::table(self::ROLES)->where('id', $second)->delete();

        self::assertSame([$third], DB::table(self::EXCLUSIONS)->pluck('excluded_role_id')->all());

        DB::table(self::ROLES)->where('id', $first)->delete();

        self::assertSame(0, DB::table(self::EXCLUSIONS)->count());
    }

    /**
     * Migrating onto a table that already exists is refused, and the table is
     * dropped cleanly, twice over.
     *
     * @return void
     */
    public function testACollisionIsRefusedAndTheTableIsDroppedCleanly(): void
    {
        $refusal = self::refusalOf(static function (): void {
            self::runMigration(self::CREATE_EXCLUSIONS, 'up');
        });

        self::assertInstanceOf(MigrationCollisionException::class, $refusal);

        self::runMigration(self::CREATE_EXCLUSIONS, 'down');
        self::runMigration(self::CREATE_EXCLUSIONS, 'down');

        self::assertFalse(Schema::hasTable(self::EXCLUSIONS));

        self::runMigration(self::CREATE_EXCLUSIONS, 'up');

        self::assertTrue(Schema::hasTable(self::EXCLUSIONS));
    }

    /**
     * Insert a role into the custom roles table and return its key.
     *
     * @param  string  $name
     * @return string
     */
    private static function role(string $name): string
    {
        $id = (string) Str::uuid();

        DB::table(self::ROLES)->insert(['id' => $id, 'name' => $name]);

        return $id;
    }

    /**
     * Run the package migration of the given file name in the given direction.
     *
     * @param  string  $file
     * @param  string  $direction
     * @return void
     */
    private static function runMigration(string $file, string $direction): void
    {
        $migration = require __DIR__ . '/../../../database/migrations/' . $file . '.php';

        \assert($migration instanceof Migration && \method_exists($migration, 'up') && \method_exists($migration, 'down'));

        $direction === 'up' ? $migration->up() : $migration->down();
    }
}
