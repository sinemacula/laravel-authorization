<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Authorization\Config\TableConfigValidator;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\TestCase;

/**
 * Feature tests for the shipped migrations under `tables.prefix`, on every
 * database: each table left at its default is created with the longest prefix
 * allowed before its name, one set explicitly under the name as written, every
 * index and key name they build fits in the limit, the models read and write
 * the prefixed tables, and the tables are dropped cleanly again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class TablePrefixMigrationTest extends TestCase
{
    /** @var string The prefix, the longest allowed. */
    private const string PREFIX = 'tp_prefix_check_';

    /** @var string The name the guardrails table is set to explicitly. */
    private const string EXPLICIT = 'tp_explicit_rails';

    /** @var list<string> The package migrations, in the order they run. */
    private const array MIGRATIONS = [
        '2026_04_14_000001_create_roles_table',
        '2026_04_14_000002_create_permissions_table',
        '2026_04_14_000003_create_policies_table',
        '2026_04_14_000004_create_role_permissions_table',
        '2026_04_14_000005_create_authorizable_roles_table',
        '2026_04_14_000006_create_authorizable_permissions_table',
        '2026_04_14_000007_create_authorizable_policies_table',
        '2026_04_14_000008_create_resource_policies_table',
        '2026_04_14_000009_create_authorizable_boundaries_table',
        '2026_04_14_000010_create_guardrails_table',
        '2026_11_08_000001_add_access_review_indexes',
        '2026_11_09_000001_create_grant_usage_tables',
        '2026_11_11_000001_add_half_tenant_indexes',
    ];

    /**
     * Set the prefix, leave every table but the guardrails at its default (the
     * permissions table set to its own name, which is the default too), and
     * create the tables beside the ones the test process migrated once under
     * the default names, so the shared schema of a parallel worker is never
     * changed.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('authorization.tables.prefix', self::PREFIX);
        $config->set('authorization.tables.permissions', 'permissions');
        $config->set('authorization.tables.guardrails', self::EXPLICIT);

        foreach (self::MIGRATIONS as $file) {
            self::runMigration($file, 'up');
        }
    }

    /**
     * Drop the prefixed tables again, children first, so a database whose
     * schema changes are not rolled back with the test's transaction, as
     * MySQL's are not, is left as it was found.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (\array_reverse(self::MIGRATIONS) as $file) {
            self::runMigration($file, 'down');
        }

        parent::tearDown();
    }

    /**
     * Every table left at its default is created with the prefix before its
     * name, the one set explicitly under its name as written, and each is the
     * name the package reads; the validator accepts the configuration.
     *
     * @return void
     */
    public function testEachDefaultTableIsCreatedWithThePrefix(): void
    {
        TableConfigValidator::validate(config('authorization.tables'));

        foreach (\array_keys(TableConfigValidator::LENGTHS) as $key) {
            $table = $key === 'guardrails' ? self::EXPLICIT : self::PREFIX . $key;

            self::assertSame($table, TableNames::get($key));
            self::assertTrue(Schema::hasTable($table), $table);
        }

        self::assertFalse(Schema::hasTable(self::PREFIX . 'guardrails'));
        self::assertTrue(Schema::hasIndex(self::PREFIX . 'authorizable_roles', ['granted_by_type', 'granted_by_id']));
        self::assertTrue(Schema::hasIndex(self::PREFIX . 'role_permissions', ['permission_id']));

        foreach ([self::PREFIX . 'policies', self::PREFIX . 'resource_policies', self::EXPLICIT] as $table) {
            self::assertTrue(Schema::hasIndex($table, $table . '_tenant_id_index'), $table);
        }
    }

    /**
     * Every index, unique index and foreign key name the migrations build on
     * the prefixed tables, as the database keeps it, fits in the limit, and
     * each foreign key references the prefixed table, or the one named
     * explicitly.
     *
     * @return void
     */
    public function testEveryNameBuiltFitsAndEveryKeyReferencesThePrefixedTables(): void
    {
        foreach (\array_keys(TableConfigValidator::LENGTHS) as $key) {
            $table = TableNames::get($key);

            foreach ([...Schema::getIndexes($table), ...Schema::getForeignKeys($table)] as $entry) {
                $name = $entry['name'] ?? '';

                self::assertLessThanOrEqual(TableConfigValidator::IDENTIFIER_LENGTH, \strlen($name), $name);
            }
        }

        $references = \array_map(static fn (array $key): string => $key['foreign_table'], Schema::getForeignKeys(self::PREFIX . 'role_permissions'));
        $rails      = \array_map(static fn (array $key): string => $key['foreign_table'], Schema::getForeignKeys(self::EXPLICIT));

        \sort($references);

        self::assertSame([self::PREFIX . 'permissions', self::PREFIX . 'roles'], $references);
        self::assertSame([self::PREFIX . 'policies'], $rails);
    }

    /**
     * The models read and write the prefixed tables, never the ones under the
     * default names.
     *
     * @return void
     */
    public function testTheModelsUseThePrefixedTables(): void
    {
        $role       = Role::create(['name' => 'prefixed-role']);
        $permission = Permission::create(['name' => 'prefixed.permission']);

        self::assertSame(self::PREFIX . 'roles', $role->getTable());
        self::assertTrue(DB::table(self::PREFIX . 'roles')->where('name', 'prefixed-role')->exists());
        self::assertTrue(DB::table(self::PREFIX . 'permissions')->where('name', 'prefixed.permission')->exists());
        self::assertFalse(DB::table('roles')->where('name', 'prefixed-role')->exists());
        self::assertSame($permission->getKey(), Permission::query()->where('name', 'prefixed.permission')->value('id'));
    }

    /**
     * Reversed, the migrations drop every prefixed table, and leave the tables
     * under the default names in place.
     *
     * @return void
     */
    public function testTheTablesAreDroppedCleanly(): void
    {
        foreach (\array_reverse(self::MIGRATIONS) as $file) {
            self::runMigration($file, 'down');
        }

        foreach (\array_keys(TableConfigValidator::LENGTHS) as $key) {
            self::assertFalse(Schema::hasTable(TableNames::get($key)), $key);
            self::assertTrue(Schema::hasTable($key), $key);
        }

        foreach (self::MIGRATIONS as $file) {
            self::runMigration($file, 'up');
        }
    }

    /**
     * Run the package migration in the file in the direction given.
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
