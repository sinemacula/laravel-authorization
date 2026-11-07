<?php

declare(strict_types = 1);

namespace Tests\Feature\Query;

use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Query\Contracts\Dialect;
use SineMacula\Laravel\Authorization\Query\Dialects\Dialects;
use SineMacula\Laravel\Authorization\Query\SchemaInspector;
use Tests\TestCase;

/**
 * Feature tests for what a query scope reads of a table and a connection, once
 * each.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SchemaInspector::class)]
final class SchemaInspectorTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A table's columns are read once, keyed by name, and another table's
     * apart; an inspector bound by the service provider lasts the request.
     *
     * @return void
     */
    public function testATablesColumnsAreReadOnce(): void
    {
        $inspector = new SchemaInspector;
        $reads     = 0;

        DB::listen(static function () use (&$reads): void {
            $reads++;
        });

        $columns = $inspector->columns(DB::connection(), 'scoped_posts');
        $before  = $reads;

        self::assertSame(['id', 'title', 'status', 'tenant_type', 'tenant_id'], \array_keys($columns));
        self::assertSame('id', $columns['id']['name']);
        self::assertSame($columns, $inspector->columns(DB::connection(), 'scoped_posts'));
        self::assertSame($before, $reads);
        self::assertArrayHasKey('team_id', $inspector->columns(DB::connection(), 'scoped_tickets'));
        self::assertGreaterThan($before, $reads);
        $app = $this->app;

        self::assertNotNull($app);
        self::assertSame($app->make(SchemaInspector::class), $app->make(SchemaInspector::class));
    }

    /**
     * The same table on another connection is read apart, once.
     *
     * @return void
     */
    public function testTheSameTableOnAnotherConnectionIsReadApart(): void
    {
        config()->set('database.connections.other', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);

        /** @var \Illuminate\Database\Connection $other */
        $other = DB::connection('other');

        $other->statement('create table scoped_posts (id integer primary key, other_col text)');

        $inspector = new SchemaInspector;
        $reads     = 0;

        self::assertSame(['id', 'title', 'status', 'tenant_type', 'tenant_id'], \array_keys($inspector->columns(DB::connection(), 'scoped_posts')));
        self::assertSame(['id', 'other_col'], \array_keys($inspector->columns($other, 'scoped_posts')));

        $other->listen(static function () use (&$reads): void {
            $reads++;
        });

        self::assertSame(['id', 'other_col'], \array_keys($inspector->columns($other, 'scoped_posts')));
        self::assertSame(0, $reads);
    }

    /**
     * Whether a connection is UTF-8 is asked of its dialect once.
     *
     * @return void
     */
    public function testAConnectionsEncodingIsAskedOnce(): void
    {
        /** @var \Illuminate\Database\Connection $connection */
        $connection = DB::connection();
        $dialect    = \Mockery::mock(Dialect::class);

        $dialect->shouldReceive('isUtf8')->once()->with($connection)->andReturn(false);

        $inspector = new SchemaInspector;

        self::assertFalse($inspector->isUtf8($connection, $dialect));
        self::assertFalse($inspector->isUtf8($connection, $dialect));

        $real = Dialects::for($connection->getDriverName());

        self::assertNotNull($real);
        self::assertTrue((new SchemaInspector)->isUtf8($connection, $real));
        self::assertInstanceOf(Connection::class, $connection);
    }

    /**
     * Whether a column compares bytes and whether an integer key holds only
     * what PHP reads are asked of the dialect once per column; a column the
     * table lacks is neither.
     *
     * @return void
     */
    public function testAColumnsExactnessIsAskedOnce(): void
    {
        $connection = DB::connection();
        $dialect    = \Mockery::mock(Dialect::class);
        $inspector  = new SchemaInspector;

        $dialect->shouldReceive('isExactCollation')->once()->andReturn(false);
        $dialect->shouldReceive('isExactInteger')->once()->andReturn(true);

        self::assertFalse($inspector->isExactCollation($connection, $dialect, 'scoped_documents', 'code'));
        self::assertFalse($inspector->isExactCollation($connection, $dialect, 'scoped_documents', 'code'));
        self::assertTrue($inspector->isExactInteger($connection, $dialect, 'scoped_posts', 'id'));
        self::assertTrue($inspector->isExactInteger($connection, $dialect, 'scoped_posts', 'id'));
        self::assertFalse($inspector->isExactCollation($connection, $dialect, 'scoped_documents', 'missing'));
        self::assertFalse($inspector->isExactInteger($connection, $dialect, 'scoped_posts', 'missing'));
    }

    /**
     * On PostgreSQL a schema-qualified table is found with the connection's
     * prefix before the table's own name, as Laravel finds it, so a
     * nondeterministic column there is not exact; a table not found is not
     * exact either.
     *
     * @return void
     */
    public function testAPrefixedTableInASchemaIsFoundOnPostgres(): void
    {
        if (DB::connection()->getDriverName() !== 'pgsql') {
            self::markTestSkipped('The relation lookup is PostgreSQL\'s.');
        }

        DB::statement('CREATE COLLATION IF NOT EXISTS authz_folded (provider = icu, locale = \'und-u-ks-level2\', deterministic = false)');
        DB::statement('CREATE SCHEMA IF NOT EXISTS authz_probe');
        DB::statement('CREATE TABLE authz_probe.pre_docs (folded varchar(191) COLLATE authz_folded, plain varchar(191), id integer)');

        // A copy of the connection, in the test's own transaction, with a
        // prefix.
        $prefixed = clone DB::connection();
        $dialect  = Dialects::for('pgsql');

        self::assertInstanceOf(Connection::class, $prefixed);

        $prefixed->setTablePrefix('pre_');

        self::assertNotNull($dialect);
        self::assertFalse($dialect->isExactCollation($prefixed, 'authz_probe.docs', ['name' => 'folded']));
        self::assertTrue($dialect->isExactCollation($prefixed, 'authz_probe.docs', ['name' => 'plain']));
        self::assertTrue($dialect->isExactCollation($prefixed, 'authz_probe.docs', ['name' => 'id']));
        self::assertFalse($dialect->isExactCollation($prefixed, 'authz_probe.missing', ['name' => 'plain']));
        self::assertFalse($dialect->isExactCollation($prefixed, 'authz_probe.docs', ['name' => 'missing']));
        self::assertFalse((new SchemaInspector)->isExactCollation($prefixed, $dialect, 'authz_probe.docs', 'folded'));

        DB::statement('DROP SCHEMA authz_probe CASCADE');
    }
}
