<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use Tests\TestCase;

/**
 * Feature tests for the migration adding the indexes access reviews read
 * through (AUTHZ-11.6, N95): an index on the `granted_by` pair of each grant
 * table and one on the permission of each role permission edge, on the tables
 * configured under their custom names, created and dropped cleanly, and run
 * again harmlessly, on every database; a database that indexes the edge's
 * permission for its foreign key already, as MySQL does, keeps that index.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class ReviewIndexesMigrationTest extends TestCase
{
    /** @var array<string, string> The custom name of each table the migration indexes. */
    private const array TABLES = [
        'authorizable_roles'       => 'rv_authorizable_roles',
        'authorizable_permissions' => 'rv_authorizable_permissions',
        'authorizable_policies'    => 'rv_authorizable_policies',
        'role_permissions'         => 'rv_role_permissions',
    ];

    /** @var list<string> The package migrations that create the tables the review indexes reach, parents first. */
    private const array CREATES = [
        '2026_04_14_000001_create_roles_table',
        '2026_04_14_000002_create_permissions_table',
        '2026_04_14_000003_create_policies_table',
        '2026_04_14_000004_create_role_permissions_table',
        '2026_04_14_000005_create_authorizable_roles_table',
        '2026_04_14_000006_create_authorizable_permissions_table',
        '2026_04_14_000007_create_authorizable_policies_table',
    ];

    /** @var string The migration under test. */
    private const string INDEXES = '2026_11_08_000001_add_access_review_indexes';

    /**
     * Point the package at custom table names and create those tables beside
     * the ones the test process migrated once under the default names, so the
     * shared schema of a parallel worker is never changed, then add the review
     * indexes to them.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('authorization.tables.roles', 'rv_roles');
        $config->set('authorization.tables.permissions', 'rv_permissions');
        $config->set('authorization.tables.policies', 'rv_policies');

        foreach (self::TABLES as $key => $table) {
            $config->set('authorization.tables.' . $key, $table);
        }

        foreach (self::CREATES as $file) {
            self::runMigration($file, 'up');
        }

        self::migrate('up');
    }

    /**
     * Drop the custom tables again, children first, so a database whose schema
     * changes are not rolled back with the test's transaction, as MySQL's are
     * not, is left as it was found.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (\array_reverse(self::CREATES) as $file) {
            self::runMigration($file, 'down');
        }

        parent::tearDown();
    }

    /**
     * The indexes exist once the package is migrated, are dropped when the
     * migration is reversed, and are made again when it runs again, twice over,
     * on the tables' custom names.
     *
     * @return void
     */
    public function testTheIndexesAreCreatedAndDroppedCleanly(): void
    {
        self::assertIndexed(true);

        self::migrate('down');

        self::assertIndexed(false);

        self::migrate('down');
        self::migrate('up');

        self::assertIndexed(true);

        self::migrate('up');

        self::assertIndexed(true);
    }

    /**
     * A review of an actor's grants is matched on the new index, and the edges
     * of a permission are found by an index on their permission, whatever names
     * the tables are given.
     *
     * @return void
     */
    public function testTheIndexesCoverTheReviewColumns(): void
    {
        foreach (['authorizable_roles', 'authorizable_permissions', 'authorizable_policies'] as $key) {
            $table = self::TABLES[$key];

            self::assertTrue(Schema::hasIndex($table, ['granted_by_type', 'granted_by_id']), $table);
        }

        self::assertTrue(Schema::hasIndex(self::TABLES['role_permissions'], ['permission_id']));
    }

    /**
     * Assert each index the migration adds exists, or does not; the edges' own
     * index exists only where the database had none on the permission.
     *
     * @param  bool  $isIndexed
     * @return void
     */
    private static function assertIndexed(bool $isIndexed): void
    {
        foreach (['authorizable_roles', 'authorizable_permissions', 'authorizable_policies'] as $key) {
            $table = self::TABLES[$key];

            self::assertSame($isIndexed, Schema::hasIndex($table, $table . '_granted_by_index'), $table);
        }

        $edges        = self::TABLES['role_permissions'];
        $isForeignKey = DB::connection()->getDriverName() === 'mysql';

        self::assertSame($isIndexed && !$isForeignKey, Schema::hasIndex($edges, $edges . '_permission_id_index'));
        self::assertSame($isIndexed || $isForeignKey, Schema::hasIndex($edges, ['permission_id']));
    }

    /**
     * Run the migration adding the review indexes up or down.
     *
     * @param  string  $direction
     * @return void
     */
    private static function migrate(string $direction): void
    {
        self::runMigration(self::INDEXES, $direction);
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
