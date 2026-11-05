<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Grammars\MySqlGrammar;
use Illuminate\Database\Query\Grammars\PostgresGrammar;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\NullFoldingUniqueIndex;
use Tests\TestCase;

/**
 * Feature tests for the unique index in which a null counts as a value: the
 * statement it builds for each database. That the indexes hold on the test
 * database is covered by the uniqueness tests of the tables that use them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(NullFoldingUniqueIndex::class)]
final class NullFoldingUniqueIndexTest extends TestCase
{
    /**
     * Each nullable column is compared with its null folded to an empty string,
     * after the columns compared as stored.
     *
     * @return void
     */
    public function testCreateFoldsEachNullableColumn(): void
    {
        $connection = $this->connectionExpecting(
            'pgsql',
            'CREATE UNIQUE INDEX "grants_unique" ON "grants" ("role_id", "grantee", (COALESCE("tenant", \'\')), (COALESCE("application", \'\')))',
        );

        (new NullFoldingUniqueIndex($connection))->create('grants', 'grants_unique', ['role_id', 'grantee'], ['tenant', 'application']);
    }

    /**
     * An index that is not digested folds the nullable columns on MySQL too.
     *
     * @return void
     */
    public function testCreateDoesNotDigestOnMySql(): void
    {
        $connection = $this->connectionExpecting(
            'mysql',
            'CREATE UNIQUE INDEX `roles_unique` ON `roles` (`name`, (COALESCE(`guard`, \'\')))',
        );

        (new NullFoldingUniqueIndex($connection))->create('roles', 'roles_unique', ['name'], ['guard']);
    }

    /**
     * A digested index compares each folded nullable column by its SHA-256
     * digest on MySQL.
     *
     * @return void
     */
    public function testCreateDigestedDigestsOnMySql(): void
    {
        $connection = $this->connectionExpecting(
            'mysql',
            'CREATE UNIQUE INDEX `grants_unique` ON `grants` (`role_id`, (SHA2(COALESCE(`tenant`, \'\'), 256)), (SHA2(COALESCE(`application`, \'\'), 256)))',
        );

        (new NullFoldingUniqueIndex($connection))->createDigested('grants', 'grants_unique', ['role_id'], ['tenant', 'application']);
    }

    /**
     * A digested index folds the nullable columns without a digest on the other
     * databases.
     *
     * @return void
     */
    public function testCreateDigestedFoldsWithoutADigestElsewhere(): void
    {
        $connection = $this->connectionExpecting(
            'pgsql',
            'CREATE UNIQUE INDEX "grants_unique" ON "grants" ("role_id", (COALESCE("tenant", \'\')))',
        );

        (new NullFoldingUniqueIndex($connection))->createDigested('grants', 'grants_unique', ['role_id'], ['tenant']);
    }

    /**
     * Return a connection for the given driver, with that driver's grammar,
     * expecting exactly the given statement.
     *
     * @param  string  $driver
     * @param  string  $statement
     * @return \Illuminate\Database\Connection
     */
    private function connectionExpecting(string $driver, string $statement): Connection
    {
        $connection = \Mockery::mock(Connection::class);
        $grammar    = $driver === 'mysql' ? new MySqlGrammar($connection) : new PostgresGrammar($connection);

        $connection->shouldReceive('getTablePrefix')->andReturn('');
        $connection->shouldReceive('getDriverName')->andReturn($driver);
        $connection->shouldReceive('getQueryGrammar')->andReturn($grammar);
        $connection->shouldReceive('statement')->once()->with($statement)->andReturn(true);

        $this->addToAssertionCount(1);

        return $connection;
    }
}
