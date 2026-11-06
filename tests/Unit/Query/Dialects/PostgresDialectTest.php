<?php

declare(strict_types = 1);

namespace Tests\Unit\Query\Dialects;

use Illuminate\Database\Connection;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Query\Dialects\PostgresDialect;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;

/**
 * Unit tests for the SQL a query scope writes on PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PostgresDialect::class)]
final class PostgresDialectTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The integer types are integers, `varchar` and `text` strings, `uuid` a
     * uuid, and any other, `bpchar` included, none.
     *
     * @return void
     */
    public function testAColumnsKindIsItsType(): void
    {
        $dialect = new PostgresDialect;

        foreach (['int2', 'int4', 'INT8'] as $type) {
            self::assertSame(ColumnKind::INTEGER, $dialect->kindOf(['type_name' => $type]));
        }

        self::assertSame(ColumnKind::STRING, $dialect->kindOf(['type_name' => 'varchar']));
        self::assertSame(ColumnKind::STRING, $dialect->kindOf(['type_name' => 'text']));
        self::assertSame(ColumnKind::UUID, $dialect->kindOf(['type_name' => 'uuid']));
        self::assertNull($dialect->kindOf(['type_name' => 'bpchar']));
        self::assertNull($dialect->kindOf(['type_name' => 'numeric']));
        self::assertNull($dialect->kindOf([]));
    }

    /**
     * The connection is UTF-8 only when the server and the client encodings
     * both are.
     *
     * @return void
     */
    public function testTheServerAndTheClientMustBeUtf8(): void
    {
        $dialect = new PostgresDialect;

        self::assertTrue($dialect->isUtf8(self::connection('UTF8', 'UTF8')));
        self::assertFalse($dialect->isUtf8(self::connection('LATIN1', 'UTF8')));
        self::assertFalse($dialect->isUtf8(self::connection('UTF8', 'LATIN1')));
    }

    /**
     * The guard on a string key is that it is not null and not empty; on any
     * other, that it is not null.
     *
     * @return void
     */
    public function testTheKeyGuard(): void
    {
        $dialect = new PostgresDialect;

        self::assertSame('("k" IS NOT NULL AND octet_length("k") > 0)', $dialect->keyGuard('"k"', ColumnKind::STRING, false));
        self::assertSame('"k" IS NOT NULL', $dialect->keyGuard('"k"', ColumnKind::INTEGER, false));
        self::assertSame('"k" IS NOT NULL', $dialect->keyGuard('"k"', ColumnKind::UUID, false));
        self::assertSame('"k" IS NOT NULL', $dialect->keyGuard('"k"', ColumnKind::STRING, true));
    }

    /**
     * Only a string key's length is unbounded.
     *
     * @return void
     */
    public function testTheKeyLength(): void
    {
        $dialect = new PostgresDialect;

        self::assertSame('octet_length("k")', $dialect->keyLength('"k"', ColumnKind::STRING, false));
        self::assertNull($dialect->keyLength('"k"', ColumnKind::INTEGER, false));
        self::assertNull($dialect->keyLength('"k"', ColumnKind::UUID, false));
        self::assertNull($dialect->keyLength('"k"', ColumnKind::STRING, true));
    }

    /**
     * A column equals a value when the UTF-8 bytes of its text are the value's,
     * given in hex.
     *
     * @return void
     */
    public function testAColumnEqualsAValueByItsBytes(): void
    {
        self::assertSame('convert_to(CAST("c" AS TEXT), \'UTF8\') = decode(\'612762\', \'hex\')', (new PostgresDialect)->equalsBytes('"c"', 'a\'b'));
    }

    /**
     * Return a connection reporting the encodings.
     *
     * @param  string  $server
     * @param  string  $client
     * @return \Illuminate\Database\Connection
     */
    private static function connection(string $server, string $client): Connection
    {
        $connection = \Mockery::mock(Connection::class);

        $connection->shouldReceive('selectOne')->with('SHOW server_encoding')->andReturn((object) ['server_encoding' => $server]);
        $connection->shouldReceive('selectOne')->with('SHOW client_encoding')->andReturn((object) ['client_encoding' => $client]);

        return $connection;
    }
}
