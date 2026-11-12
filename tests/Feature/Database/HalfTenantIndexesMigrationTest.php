<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use Tests\TestCase;

/**
 * Feature tests for the migration adding the indexes the rows naming half a
 * tenant are found through (N130): an index on `tenant_id` and then
 * `tenant_type` of the guardrails, the resource policies and the policies, on
 * the tables configured under their custom names, created and dropped cleanly,
 * and run again harmlessly, on every database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class HalfTenantIndexesMigrationTest extends TestCase
{
    /** @var array<string, string> The custom name of each table the migration indexes. */
    private const array TABLES = [
        'policies'          => 'ht_policies',
        'resource_policies' => 'ht_resource_policies',
        'guardrails'        => 'ht_guardrails',
    ];

    /** @var list<string> The package migrations that create the tables indexed, parents first. */
    private const array CREATES = [
        '2026_04_14_000003_create_policies_table',
        '2026_04_14_000008_create_resource_policies_table',
        '2026_04_14_000010_create_guardrails_table',
    ];

    /** @var string The migration under test. */
    private const string INDEXES = '2026_11_11_000001_add_half_tenant_indexes';

    /**
     * Point the package at custom table names and create those tables beside
     * the ones the test process migrated once under the default names, so the
     * shared schema of a parallel worker is never changed, then add the indexes
     * to them.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        foreach (self::TABLES as $key => $table) {
            $config->set('authorization.tables.' . $key, $table);
        }

        foreach (self::CREATES as $file) {
            self::runMigration($file, 'up');
        }

        self::runMigration(self::INDEXES, 'up');
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
     * The indexes exist once the package is migrated, on the key and then the
     * type, are dropped when the migration is reversed, and are made again when
     * it runs again, twice over, on the tables' custom names.
     *
     * @return void
     */
    public function testTheIndexesAreCreatedAndDroppedCleanly(): void
    {
        self::assertIndexed(true);

        self::runMigration(self::INDEXES, 'down');

        self::assertIndexed(false);

        self::runMigration(self::INDEXES, 'down');
        self::runMigration(self::INDEXES, 'up');

        self::assertIndexed(true);

        self::runMigration(self::INDEXES, 'up');

        self::assertIndexed(true);
    }

    /**
     * Assert each index the migration adds exists, on the key and then the
     * type, or does not.
     *
     * @param  bool  $isIndexed
     * @return void
     */
    private static function assertIndexed(bool $isIndexed): void
    {
        foreach (self::TABLES as $table) {
            self::assertSame($isIndexed, Schema::hasIndex($table, $table . '_tenant_id_index'), $table);
            self::assertSame($isIndexed, Schema::hasIndex($table, ['tenant_id', 'tenant_type']), $table);
        }
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
