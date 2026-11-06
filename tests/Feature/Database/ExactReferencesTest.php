<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Database\Connection;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\ExactReferences;
use Tests\TestCase;

/**
 * Feature tests for the byte-exact collation of the reference columns: which
 * columns it gives the collation, and on which database. That a check and the
 * unique keys then tell near twins apart is covered by
 * `ExactReferenceMatchingTest`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExactReferences::class)]
final class ExactReferencesTest extends TestCase
{
    /**
     * On MySQL each reference column takes the byte-exact collation and its
     * character set, and every other column keeps the table's.
     *
     * @return void
     */
    public function testGivesTheReferenceColumnsTheByteExactCollationOnMySql(): void
    {
        $blueprint = self::blueprint();

        (new ExactReferences(self::connectionFor('mysql')))->apply($blueprint);

        foreach (self::columnsOf($blueprint) as $name => $column) {
            $reference = \in_array($name, ExactReferences::COLUMNS, true);

            self::assertSame($reference ? 'utf8mb4_0900_bin' : null, $column->get('collation'), $name);
            self::assertSame($reference ? 'utf8mb4' : null, $column->get('charset'), $name);
        }
    }

    /**
     * The other databases already compare the columns' exact bytes, so no
     * column is changed there.
     *
     * @return void
     */
    public function testLeavesTheColumnsAloneElsewhere(): void
    {
        foreach (['pgsql', 'sqlite', 'mariadb'] as $driver) {
            $blueprint = self::blueprint();

            (new ExactReferences(self::connectionFor($driver)))->apply($blueprint);

            foreach (self::columnsOf($blueprint) as $name => $column) {
                self::assertNull($column->get('collation'), $driver . ': ' . $name);
                self::assertNull($column->get('charset'), $driver . ': ' . $name);
            }
        }
    }

    /**
     * Return a blueprint adding a name, a guard and a column of each reference.
     *
     * @return \Illuminate\Database\Schema\Blueprint
     */
    private static function blueprint(): Blueprint
    {
        /** @var \Illuminate\Database\Connection $connection */
        $connection = DB::connection();

        // The connection's schema grammar is only set once a schema builder has
        // been asked for, and a blueprint needs it.
        $connection->useDefaultSchemaGrammar();

        $blueprint = new Blueprint($connection, 'things');

        $blueprint->string('name', 191);
        $blueprint->string('guard', 64)->nullable();

        foreach (ExactReferences::COLUMNS as $column) {
            $blueprint->string($column, 191)->nullable();
        }

        return $blueprint;
    }

    /**
     * Return the columns the blueprint adds, by name.
     *
     * @param  \Illuminate\Database\Schema\Blueprint  $blueprint
     * @return array<string, \Illuminate\Database\Schema\ColumnDefinition>
     */
    private static function columnsOf(Blueprint $blueprint): array
    {
        $columns = [];

        foreach ($blueprint->getAddedColumns() as $column) {
            /** @var string $name */
            $name           = $column->get('name');
            $columns[$name] = $column;
        }

        self::assertCount(2 + \count(ExactReferences::COLUMNS), $columns);

        return $columns;
    }

    /**
     * Return a connection that reports the given driver.
     *
     * @param  string  $driver
     * @return \Illuminate\Database\Connection
     */
    private static function connectionFor(string $driver): Connection
    {
        $connection = \Mockery::mock(Connection::class);

        $connection->shouldReceive('getDriverName')->andReturn($driver);

        return $connection;
    }
}
