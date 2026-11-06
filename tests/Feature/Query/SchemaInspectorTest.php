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
}
