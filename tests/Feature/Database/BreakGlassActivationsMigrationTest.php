<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Authorization\Config\TableConfigValidator;
use SineMacula\Laravel\Authorization\Database\ExactReferences;
use SineMacula\Laravel\Authorization\Database\MigrationCollisionException;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\TestCase;

/**
 * Feature tests for the migration creating the break-glass activations table
 * (AUTHZ-11.7, N133), on every database: under a name set explicitly, beside
 * the roles table it references, with every column, index and key, each name it
 * builds within the limit, its reference columns byte-exact on MySQL; it
 * refuses to overwrite a table of the same name, and is dropped cleanly again.
 * The prefixed name is proven in `TablePrefixMigrationTest`, and the bound of
 * the name in `TableConfigValidatorTest`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class BreakGlassActivationsMigrationTest extends TestCase
{
    /** @var string The name the activations table is set to explicitly, the longest allowed. */
    private const string TABLE = 'bg_explicit_break_glass_activations_table_name0';

    /** @var string The name the roles table it references is set to. */
    private const string ROLES = 'bg_roles';

    /** @var string The migration under test. */
    private const string MIGRATION = '2026_11_12_000001_create_break_glass_activations_table';

    /** @var string The migration creating the roles table. */
    private const string ROLES_MIGRATION = '2026_04_14_000001_create_roles_table';

    /** @var list<string> The columns the table has, in order. */
    private const array COLUMNS = [
        'id', 'role_id', 'authorizable_type', 'authorizable_id', 'granted_by_type', 'granted_by_id', 'tenant_type', 'tenant_id', 'include_subtree', 'application',
        'justification', 'note', 'activated_at', 'expires_at', 'ended_at', 'ended_by_type', 'ended_by_id', 'end_reason',
    ];

    /**
     * Point the package at the explicit names and create the tables beside the
     * ones the test process migrated once under the default names, so the
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

        $config->set('authorization.tables.break_glass', self::TABLE);
        $config->set('authorization.tables.roles', self::ROLES);

        self::runMigration(self::ROLES_MIGRATION, 'up');
        self::runMigration(self::MIGRATION, 'up');
    }

    /**
     * Drop the tables again, children first, so a database whose schema changes
     * are not rolled back with the test's transaction, as MySQL's are not, is
     * left as it was found.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::runMigration(self::MIGRATION, 'down');
        self::runMigration(self::ROLES_MIGRATION, 'down');

        parent::tearDown();
    }

    /**
     * The table has every column, the indexes the resolution and the reviews
     * read it through, and its key onto the roles table under its explicit
     * name, every name within the limit; a role's deletion removes its
     * activations.
     *
     * @return void
     */
    public function testTheTableIsCreatedWithEveryColumnIndexAndKey(): void
    {
        self::assertSame(TableConfigValidator::LENGTHS['break_glass'], \strlen(self::TABLE));
        self::assertSame(self::COLUMNS, Schema::getColumnListing(self::TABLE));
        self::assertTrue(Schema::hasIndex(self::TABLE, ['authorizable_type', 'authorizable_id', 'expires_at']));
        self::assertTrue(Schema::hasIndex(self::TABLE, ['tenant_type', 'tenant_id']));
        self::assertTrue(Schema::hasIndex(self::TABLE, ['role_id', 'expires_at']));
        self::assertTrue(Schema::hasIndex(self::TABLE, ['id'], 'primary'));
        self::assertSame([self::ROLES], \array_column(Schema::getForeignKeys(self::TABLE), 'foreign_table'));

        foreach ([...Schema::getIndexes(self::TABLE), ...Schema::getForeignKeys(self::TABLE)] as $entry) {
            $name = $entry['name'] ?? '';

            // SQLite names the key no migration names itself, and sets no limit
            // on it.
            if (\str_starts_with($name, 'sqlite_autoindex_')) {
                continue;
            }

            self::assertLessThanOrEqual(TableConfigValidator::IDENTIFIER_LENGTH, \strlen($name), $name);
        }

        $role = Role::create(['name' => 'responder']);

        DB::table(self::TABLE)->insert([
            'id'                => '00000000-0000-4000-8000-000000000001',
            'role_id'           => $role->getKey(),
            'authorizable_type' => 'user',
            'authorizable_id'   => '1',
            'justification'     => 'incident',
            'activated_at'      => '2026-07-01 12:00:00',
            'expires_at'        => '2026-07-01 13:00:00',
        ]);

        self::assertSame('1', DB::table(self::TABLE)->value('authorizable_id'));
        self::assertContains(DB::table(self::TABLE)->value('include_subtree'), [1, '1', true]);

        DB::table(self::ROLES)->delete();

        self::assertSame(0, DB::table(self::TABLE)->count());
    }

    /**
     * On MySQL the reference columns compare their exact bytes, as the grant
     * tables' do, and no other column does.
     *
     * @return void
     */
    public function testTheReferenceColumnsCompareTheirExactBytes(): void
    {
        if (DB::connection()->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL collates the reference columns.');
        }

        $collated = [];

        foreach (Schema::getColumns(self::TABLE) as $column) {
            if ($column['collation'] !== ExactReferences::COLLATION) {
                continue;
            }

            $collated[] = $column['name'];
        }

        self::assertSame(
            ['authorizable_type', 'authorizable_id', 'granted_by_type', 'granted_by_id', 'tenant_type', 'tenant_id', 'application', 'ended_by_type', 'ended_by_id'],
            $collated,
        );
    }

    /**
     * The migration refuses to create the table over one of the same name, and
     * reversed, drops it, twice over harmlessly, leaving the roles table.
     *
     * @return void
     */
    public function testItRefusesACollisionAndIsDroppedCleanly(): void
    {
        $refusal = self::refusalOfRunningAgain();

        self::assertInstanceOf(MigrationCollisionException::class, $refusal);
        self::assertStringContainsString(self::TABLE, $refusal->getMessage());

        self::runMigration(self::MIGRATION, 'down');
        self::runMigration(self::MIGRATION, 'down');

        self::assertFalse(Schema::hasTable(self::TABLE));
        self::assertTrue(Schema::hasTable(self::ROLES));

        self::runMigration(self::MIGRATION, 'up');

        self::assertTrue(Schema::hasTable(self::TABLE));
    }

    /**
     * Run the migration under test again and return what it threw, or null when
     * it threw nothing.
     *
     * @return \Throwable|null
     */
    private static function refusalOfRunningAgain(): ?\Throwable
    {
        try {
            self::runMigration(self::MIGRATION, 'up');
        } catch (\Throwable $exception) {
            return $exception;
        }

        return null;
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
