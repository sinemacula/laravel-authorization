<?php

declare(strict_types = 1);

namespace Tests\Unit\Query\Dialects;

use Illuminate\Database\Connection;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Query\Dialects\SqliteDialect;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;

/**
 * Unit tests for the SQL a query scope writes on SQLite.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SqliteDialect::class)]
final class SqliteDialectTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A column's kind is its declared type's affinity: integer for a type
     * naming `int`, string for one naming `char`, `clob` or `text`, and none
     * for any other.
     *
     * @return void
     */
    public function testAColumnsKindIsItsAffinity(): void
    {
        $dialect = new SqliteDialect;

        self::assertSame(ColumnKind::INTEGER, $dialect->kindOf(['type' => 'INTEGER']));
        self::assertSame(ColumnKind::INTEGER, $dialect->kindOf(['type' => 'bigint']));
        self::assertSame(ColumnKind::STRING, $dialect->kindOf(['type' => 'varchar(255)']));
        self::assertSame(ColumnKind::STRING, $dialect->kindOf(['type' => 'clob']));
        self::assertSame(ColumnKind::STRING, $dialect->kindOf(['type' => 'text']));
        self::assertNull($dialect->kindOf(['type' => 'blob']));
        self::assertNull($dialect->kindOf(['type' => 'numeric']));
        self::assertNull($dialect->kindOf([]));
    }

    /**
     * The database is UTF-8 only when `PRAGMA encoding` says so.
     *
     * @return void
     */
    public function testTheDatabaseMustBeUtf8(): void
    {
        $dialect = new SqliteDialect;

        self::assertTrue($dialect->isUtf8(self::connection(['encoding' => 'UTF-8'])));
        self::assertTrue($dialect->isUtf8(self::connection(['encoding' => 'utf-8'])));
        self::assertFalse($dialect->isUtf8(self::connection(['encoding' => 'UTF-16le'])));
    }

    /**
     * The guard on a key cast to an integer is that it is not null; on any
     * other, whatever it holds, that its bytes are not empty and hold no NUL.
     *
     * @return void
     */
    public function testTheKeyGuard(): void
    {
        $dialect = new SqliteDialect;

        self::assertSame('"k" IS NOT NULL', $dialect->keyGuard('"k"', ColumnKind::INTEGER, true));
        self::assertSame('("k" IS NOT NULL AND length(CAST("k" AS BLOB)) > 0 AND instr(CAST("k" AS BLOB), X\'00\') = 0)', $dialect->keyGuard('"k"', ColumnKind::INTEGER, false));
        self::assertSame($dialect->keyGuard('"k"', ColumnKind::INTEGER, false), $dialect->keyGuard('"k"', ColumnKind::STRING, false));
    }

    /**
     * A key's length is unbounded unless it is cast to an integer.
     *
     * @return void
     */
    public function testTheKeyLength(): void
    {
        $dialect = new SqliteDialect;

        self::assertNull($dialect->keyLength('"k"', ColumnKind::INTEGER, true));
        self::assertSame('length(CAST("k" AS BLOB))', $dialect->keyLength('"k"', ColumnKind::INTEGER, false));
    }

    /**
     * A column equals a value when it holds an integer, text or a blob whose
     * bytes are the value's, given in hex.
     *
     * @return void
     */
    public function testAColumnEqualsAValueByItsBytes(): void
    {
        self::assertSame('(typeof("c") IN (\'integer\', \'text\', \'blob\') AND CAST("c" AS BLOB) = X\'612762\')', (new SqliteDialect)->equalsBytes('"c"', 'a\'b'));
        self::assertSame('(typeof("c") IN (\'integer\', \'text\', \'blob\') AND CAST("c" AS BLOB) = X\'\')', (new SqliteDialect)->equalsBytes('"c"', ''));
    }

    /**
     * A tenant column is readable when it holds no real number.
     *
     * @return void
     */
    public function testATenantColumnIsReadableUnlessItHoldsARealNumber(): void
    {
        self::assertSame('typeof("c") IN (\'null\', \'integer\', \'text\', \'blob\')', (new SqliteDialect)->readable('"c"'));
    }

    /**
     * The bare column is compared with the value as text and as a blob,
     * whatever its kind.
     *
     * @return void
     */
    public function testTheBareColumnIsComparedWithTheValueAsTextAndAsABlob(): void
    {
        $dialect = new SqliteDialect;

        foreach ([ColumnKind::STRING, ColumnKind::INTEGER] as $kind) {
            self::assertSame('"c" IN (CAST(X\'612762\' AS TEXT), X\'612762\')', $dialect->equalsIndexed('"c"', $kind, 'a\'b'));
        }
    }

    /**
     * A column compares bytes when it declares no collation or `BINARY`.
     *
     * @return void
     */
    public function testAnExactCollationIsNoneOrBinary(): void
    {
        $dialect    = new SqliteDialect;
        $connection = \Mockery::mock(Connection::class);

        self::assertTrue($dialect->isExactCollation($connection, 'posts', ['collation' => null]));
        self::assertTrue($dialect->isExactCollation($connection, 'posts', ['collation' => 'BINARY']));
        self::assertFalse($dialect->isExactCollation($connection, 'posts', ['collation' => 'nocase']));
        self::assertFalse($dialect->isExactCollation($connection, 'posts', ['collation' => 'rtrim']));
    }

    /**
     * An integer key is exact only as the rowid of a table that has one.
     *
     * @return void
     */
    public function testAnExactIntegerKeyIsTheRowid(): void
    {
        $dialect = new SqliteDialect;
        $table   = static function (string $sql): Connection {
            $connection = \Mockery::mock(Connection::class);

            $connection->shouldReceive('getTablePrefix')->andReturn('app_');
            $connection->shouldReceive('selectOne')->with('select sql from sqlite_master where type = \'table\' and name = ?', ['app_posts'])->andReturn((object) ['sql' => $sql]);

            return $connection;
        };

        self::assertTrue($dialect->isExactInteger($table('create table posts (id integer primary key)'), 'posts', ['auto_increment' => true]));
        self::assertFalse($dialect->isExactInteger($table('create table posts (id integer primary key) without rowid'), 'posts', ['auto_increment' => true]));
        self::assertFalse($dialect->isExactInteger(\Mockery::mock(Connection::class), 'posts', ['auto_increment' => false]));
    }

    /**
     * Text images, byte literals, a prefix and an attached key's text are
     * compared through blobs and `BINARY`.
     *
     * @return void
     */
    public function testTheTextFragments(): void
    {
        $dialect = new SqliteDialect;

        self::assertSame('CAST(k AS BLOB)', $dialect->textImage('k'));
        self::assertSame('X\'6162\'', $dialect->bytes('ab'));
        self::assertSame('X\'\'', $dialect->bytes(''));
        self::assertSame('substr(CAST(k AS BLOB), 1, 2) = X\'6162\'', $dialect->startsWith('k', 'ab'));
        self::assertSame('a = CAST(k AS TEXT) COLLATE BINARY', $dialect->equalsKeyText('a', 'k', [], true));
        self::assertNull($dialect->equalsKeyText('a', 'k', [], false));
    }

    /**
     * Return a connection whose one row is the given.
     *
     * @param  array<string, string>  $row
     * @return \Illuminate\Database\Connection
     */
    private static function connection(array $row): Connection
    {
        $connection = \Mockery::mock(Connection::class);

        $connection->shouldReceive('selectOne')->with('PRAGMA encoding')->andReturn((object) $row);

        return $connection;
    }
}
