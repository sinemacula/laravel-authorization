<?php

declare(strict_types = 1);

namespace Tests\Unit\Query\Dialects;

use Illuminate\Database\Connection;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Query\Dialects\PostgresDialect;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;
use SineMacula\Laravel\Authorization\Query\QueryAuthorizer;

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
        self::assertTrue($dialect->isUtf8(self::connection('utf8', 'Utf8')));
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
     * Every tenant column of a kind the scope compares is read as a string, an
     * integer or null.
     *
     * @return void
     */
    public function testEveryTenantColumnIsReadable(): void
    {
        self::assertSame(QueryAuthorizer::EVERY_ROW, (new PostgresDialect)->readable('"c"'));
    }

    /**
     * The bare column is compared with the value it could hold: text that is
     * UTF-8 with no NUL byte, an integer's decimal text, a uuid's canonical
     * text; with any other, no row is.
     *
     * @return void
     */
    public function testTheBareColumnIsComparedWithAValueItCouldHold(): void
    {
        $dialect = new PostgresDialect;
        $uuid    = '0b7e8a3c-1f2d-4c5b-9a8e-7d6c5b4a3f21';

        self::assertSame('"c" = convert_from(decode(\'612762\', \'hex\'), \'UTF8\')', $dialect->equalsIndexed('"c"', ColumnKind::STRING, 'a\'b'));
        self::assertSame(QueryAuthorizer::NO_ROW, $dialect->equalsIndexed('"c"', ColumnKind::STRING, "\xff"));
        self::assertSame(QueryAuthorizer::NO_ROW, $dialect->equalsIndexed('"c"', ColumnKind::STRING, "a\0b"));
        self::assertSame('"c" = -5', $dialect->equalsIndexed('"c"', ColumnKind::INTEGER, '-5'));

        foreach (['05', '-0', '5a', ' 5', '99999999999999999999', ''] as $value) {
            self::assertSame(QueryAuthorizer::NO_ROW, $dialect->equalsIndexed('"c"', ColumnKind::INTEGER, $value), $value);
        }

        self::assertSame("\"c\" = '{$uuid}'", $dialect->equalsIndexed('"c"', ColumnKind::UUID, $uuid));
        self::assertSame(QueryAuthorizer::NO_ROW, $dialect->equalsIndexed('"c"', ColumnKind::UUID, \strtoupper($uuid)));
        self::assertSame(QueryAuthorizer::NO_ROW, $dialect->equalsIndexed('"c"', ColumnKind::UUID, "{$uuid}x"));
    }

    /**
     * A key column is comparable with a value PostgreSQL would not raise an
     * error for: digits its integer type holds, a uuid, or UTF-8 text.
     *
     * @return void
     */
    public function testAKeyColumnIsComparableWithAValueItCouldHold(): void
    {
        $dialect = new PostgresDialect;

        self::assertTrue($dialect->isComparableKey(['type_name' => 'int2'], '32767'));
        self::assertTrue($dialect->isComparableKey(['type_name' => 'INT2'], '-32768'));
        self::assertFalse($dialect->isComparableKey(['type_name' => 'int2'], '32768'));
        self::assertFalse($dialect->isComparableKey(['type_name' => 'int2'], '-32769'));
        self::assertTrue($dialect->isComparableKey(['type_name' => 'int4'], '2147483647'));
        self::assertFalse($dialect->isComparableKey(['type_name' => 'int4'], '2147483648'));
        self::assertTrue($dialect->isComparableKey(['type_name' => 'int8'], \str_repeat('9', 18)));
        self::assertFalse($dialect->isComparableKey(['type_name' => 'int8'], \str_repeat('9', 19)));
        self::assertFalse($dialect->isComparableKey(['type_name' => 'int4'], 'abc'));
        self::assertTrue($dialect->isComparableKey(['type_name' => 'uuid'], '0B7E8A3C-1F2D-4C5B-9A8E-7D6C5B4A3F21'));
        self::assertFalse($dialect->isComparableKey(['type_name' => 'uuid'], 'not-a-uuid'));
        self::assertTrue($dialect->isComparableKey(['type_name' => 'varchar'], 'ábc'));
        self::assertFalse($dialect->isComparableKey(['type_name' => 'text'], "\xff"));
        self::assertFalse($dialect->isComparableKey([], "\xff"));
    }

    /**
     * A column compares bytes when it has no collation or a deterministic one,
     * as the catalogue says for the quoted table.
     *
     * @return void
     */
    public function testAnExactCollationIsDeterministic(): void
    {
        $dialect = new PostgresDialect;
        $column  = static function (?object $row, string $relation = '"app"."pre_Po""sts"'): Connection {
            $connection = \Mockery::mock(Connection::class);
            $catalogue  = \Mockery::on(static fn (string $query): bool => \str_contains($query, 'collisdeterministic') && \str_contains($query, 'to_regclass'));

            $connection->shouldReceive('getTablePrefix')->andReturn('pre_');
            $connection->shouldReceive('selectOne')->with($catalogue, [$relation, 'code'])->andReturn($row);

            return $connection;
        };

        self::assertTrue($dialect->isExactCollation($column((object) ['exact' => true]), 'app.Po"sts', ['name' => 'code']));
        self::assertTrue($dialect->isExactCollation($column((object) ['exact' => true], '"pre_posts"'), 'posts', ['name' => 'code']));
        self::assertFalse($dialect->isExactCollation($column((object) ['exact' => false]), 'app.Po"sts', ['name' => 'code']));
        self::assertFalse($dialect->isExactCollation($column((object) ['exact' => null]), 'app.Po"sts', ['name' => 'code']));
        self::assertFalse($dialect->isExactCollation($column(null), 'app.Po"sts', ['name' => 'code']));
        self::assertFalse($dialect->isExactCollation(\Mockery::mock(Connection::class), 'db.app.posts', ['name' => 'code']));
        self::assertTrue($dialect->isExactInteger(\Mockery::mock(Connection::class), 'posts', []));
    }

    /**
     * A value is inlined as PostgreSQL reads it bound, as text of no type:
     * null, an integer's or a boolean's digits quoted, and UTF-8 text with no
     * NUL byte with every character escaped by its code point; anything else is
     * not inlined.
     *
     * @return void
     */
    public function testAValueIsInlinedAsPostgresReadsItBound(): void
    {
        $dialect = new PostgresDialect;

        self::assertSame('NULL', $dialect->parameter(null));
        self::assertSame('\'1\'', $dialect->parameter(true));
        self::assertSame('\'0\'', $dialect->parameter(false));
        self::assertSame('\'-42\'', $dialect->parameter(-42));
        self::assertSame('U&\'\0061\003F\003F\0027\005C\00E9\+01F600\'', $dialect->parameter('a??\'\é😀'));
        self::assertSame('U&\'\'', $dialect->parameter(''));
        self::assertNull($dialect->parameter("a\0b"));
        self::assertNull($dialect->parameter("\xff"));
        self::assertNull($dialect->parameter(1.5));
    }

    /**
     * Text images, byte literals, a prefix and an attached key's text are
     * compared through the UTF-8 bytes of their text.
     *
     * @return void
     */
    public function testTheTextFragments(): void
    {
        $dialect = new PostgresDialect;

        self::assertSame('convert_to(CAST(k AS TEXT), \'UTF8\')', $dialect->textImage('k'));
        self::assertSame('decode(\'6162\', \'hex\')', $dialect->bytes('ab'));
        self::assertSame('substring(convert_to(CAST(k AS TEXT), \'UTF8\') from 1 for 2) = decode(\'6162\', \'hex\')', $dialect->startsWith('k', 'ab'));
        self::assertSame('convert_to(a, \'UTF8\') = convert_to(CAST(k AS TEXT), \'UTF8\')', $dialect->equalsKeyText('a', 'k', [], true));
        self::assertNull($dialect->equalsKeyText('a', 'k', [], false));
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
