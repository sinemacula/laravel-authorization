<?php

declare(strict_types = 1);

namespace Tests\Unit\Query\Dialects;

use Illuminate\Database\Connection;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Query\Dialects\MySqlDialect;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;
use SineMacula\Laravel\Authorization\Query\QueryAuthorizer;

/**
 * Unit tests for the SQL a query scope writes on MySQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MySqlDialect::class)]
final class MySqlDialectTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The integer types are integers, and the character and text types strings
     * when their collation is a utf8mb4 one; any other is none.
     *
     * @return void
     */
    public function testAColumnsKindIsItsTypeAndCharacterSet(): void
    {
        $dialect = new MySqlDialect;

        foreach (['tinyint', 'smallint', 'mediumint', 'int', 'integer', 'BIGINT'] as $type) {
            self::assertSame(ColumnKind::INTEGER, $dialect->kindOf(['type_name' => $type]));
        }

        foreach (['char', 'varchar', 'tinytext', 'text', 'mediumtext', 'longtext'] as $type) {
            self::assertSame(ColumnKind::STRING, $dialect->kindOf(['type_name' => $type, 'collation' => 'utf8mb4_unicode_ci']));
            self::assertNull($dialect->kindOf(['type_name' => $type, 'collation' => 'latin1_swedish_ci']));
        }

        self::assertNull($dialect->kindOf(['type_name' => 'varchar']));
        self::assertNull($dialect->kindOf(['type_name' => 'varbinary', 'collation' => 'utf8mb4_bin']));
        self::assertNull($dialect->kindOf(['type_name' => 'decimal']));
    }

    /**
     * The connection is UTF-8 only when its client, connection and results
     * character sets are all utf8mb4.
     *
     * @return void
     */
    public function testEveryCharacterSetMustBeUtf8mb4(): void
    {
        $dialect = new MySqlDialect;

        self::assertTrue($dialect->isUtf8(self::connection(['client' => 'utf8mb4', 'connection' => 'UTF8MB4', 'results' => 'utf8mb4'])));
        self::assertFalse($dialect->isUtf8(self::connection(['client' => 'utf8mb4', 'connection' => 'latin1', 'results' => 'utf8mb4'])));
        self::assertFalse($dialect->isUtf8(self::connection(['client' => 'utf8mb4', 'connection' => 'utf8mb4', 'results' => null])));
        self::assertFalse($dialect->isUtf8(self::connection([])));
    }

    /**
     * The guard on a string key is that it is not null, not empty and holds no
     * NUL byte; on any other, that it is not null.
     *
     * @return void
     */
    public function testTheKeyGuard(): void
    {
        $dialect = new MySqlDialect;

        self::assertSame('(`k` IS NOT NULL AND OCTET_LENGTH(`k`) > 0 AND LOCATE(X\'00\', CAST(`k` AS BINARY)) = 0)', $dialect->keyGuard('`k`', ColumnKind::STRING, false));
        self::assertSame('`k` IS NOT NULL', $dialect->keyGuard('`k`', ColumnKind::INTEGER, false));
        self::assertSame('`k` IS NOT NULL', $dialect->keyGuard('`k`', ColumnKind::STRING, true));
    }

    /**
     * Only a string key's length is unbounded.
     *
     * @return void
     */
    public function testTheKeyLength(): void
    {
        $dialect = new MySqlDialect;

        self::assertSame('OCTET_LENGTH(`k`)', $dialect->keyLength('`k`', ColumnKind::STRING, false));
        self::assertNull($dialect->keyLength('`k`', ColumnKind::INTEGER, false));
        self::assertNull($dialect->keyLength('`k`', ColumnKind::STRING, true));
    }

    /**
     * A column equals a value when its bytes are the value's, given in hex.
     *
     * @return void
     */
    public function testAColumnEqualsAValueByItsBytes(): void
    {
        self::assertSame('CAST(`c` AS BINARY) = X\'612762\'', (new MySqlDialect)->equalsBytes('`c`', 'a\'b'));
    }

    /**
     * Every tenant column of a kind the scope compares is read as a string, an
     * integer or null.
     *
     * @return void
     */
    public function testEveryTenantColumnIsReadable(): void
    {
        self::assertSame(QueryAuthorizer::EVERY_ROW, (new MySqlDialect)->readable('`c`'));
    }

    /**
     * The bare column is compared with the value it could hold: a string column
     * with UTF-8 as a utf8mb4 literal, an integer column with an integer's
     * decimal text, unsigned ones beyond PHP's integers included; with any
     * other, no row is.
     *
     * @return void
     */
    public function testTheBareColumnIsComparedWithAValueItCouldHold(): void
    {
        $dialect = new MySqlDialect;

        self::assertSame('`c` = _utf8mb4 X\'612762\'', $dialect->equalsIndexed('`c`', ColumnKind::STRING, 'a\'b'));
        self::assertSame(QueryAuthorizer::NO_ROW, $dialect->equalsIndexed('`c`', ColumnKind::STRING, "\xff"));
        self::assertSame('`c` = 18446744073709551615', $dialect->equalsIndexed('`c`', ColumnKind::INTEGER, '18446744073709551615'));
        self::assertSame('`c` = -5', $dialect->equalsIndexed('`c`', ColumnKind::INTEGER, '-5'));
        self::assertSame('`c` = 0', $dialect->equalsIndexed('`c`', ColumnKind::INTEGER, '0'));

        foreach (['05', '-0', '5a', ' 5', \str_repeat('9', 21), ''] as $value) {
            self::assertSame(QueryAuthorizer::NO_ROW, $dialect->equalsIndexed('`c`', ColumnKind::INTEGER, $value), $value);
        }

        self::assertSame(QueryAuthorizer::NO_ROW, $dialect->equalsIndexed('`c`', ColumnKind::UUID, 'a'));
    }

    /**
     * A column compares bytes when it has no collation, `utf8mb4_0900_bin` or
     * `binary`; a case-insensitive or padding one does not.
     *
     * @return void
     */
    public function testAnExactCollationComparesBytesWithoutPadding(): void
    {
        $dialect    = new MySqlDialect;
        $connection = \Mockery::mock(Connection::class);

        self::assertTrue($dialect->isExactCollation($connection, 'posts', ['collation' => null]));
        self::assertTrue($dialect->isExactCollation($connection, 'posts', ['collation' => 'utf8mb4_0900_bin']));
        self::assertTrue($dialect->isExactCollation($connection, 'posts', ['collation' => 'binary']));
        self::assertTrue($dialect->isExactCollation($connection, 'posts', ['collation' => 'UTF8MB4_0900_BIN']));
        self::assertTrue($dialect->isExactCollation($connection, 'posts', ['collation' => 'BINARY']));
        self::assertFalse($dialect->isExactCollation($connection, 'posts', ['collation' => 'utf8mb4_unicode_ci']));
        self::assertFalse($dialect->isExactCollation($connection, 'posts', ['collation' => 'utf8mb4_bin']));
    }

    /**
     * An unsigned `BIGINT` key is not exact, nor is a `ZEROFILL` one of any
     * size, signed or not; every other integer type is.
     *
     * @return void
     */
    public function testAnUnsignedBigintKeyIsNotExact(): void
    {
        $dialect    = new MySqlDialect;
        $connection = \Mockery::mock(Connection::class);

        self::assertFalse($dialect->isExactInteger($connection, 'posts', ['type' => 'bigint unsigned']));
        self::assertFalse($dialect->isExactInteger($connection, 'posts', ['type' => 'BIGINT UNSIGNED']));
        self::assertFalse($dialect->isExactInteger($connection, 'posts', ['type' => 'int(5) unsigned zerofill']));
        self::assertFalse($dialect->isExactInteger($connection, 'posts', ['type' => 'INT(5) ZEROFILL']));
        self::assertTrue($dialect->isExactInteger($connection, 'posts', ['type' => 'bigint']));
        self::assertTrue($dialect->isExactInteger($connection, 'posts', ['type' => 'int unsigned']));
        self::assertTrue($dialect->isExactInteger($connection, 'posts', []));
    }

    /**
     * Text images, byte literals, a prefix and an attached key's text, the last
     * under the attachment column's own utf8mb4 collation.
     *
     * @return void
     */
    public function testTheTextFragments(): void
    {
        $dialect = new MySqlDialect;

        self::assertSame('CAST(CAST(k AS CHAR CHARACTER SET utf8mb4) AS BINARY)', $dialect->textImage('k'));
        self::assertSame('X\'6162\'', $dialect->bytes('ab'));
        self::assertSame('LEFT(CAST(k AS BINARY), 2) = X\'6162\'', $dialect->startsWith('k', 'ab'));
        self::assertSame('a = CAST(k AS CHAR CHARACTER SET utf8mb4) COLLATE utf8mb4_unicode_ci', $dialect->equalsKeyText('a', 'k', ['collation' => 'utf8mb4_unicode_ci'], false));
        self::assertSame('a = CAST(k AS CHAR CHARACTER SET utf8mb4) COLLATE utf8mb4_unicode_ci', $dialect->equalsKeyText('a', 'k', ['collation' => 'UTF8MB4_UNICODE_CI'], false));
        self::assertNull($dialect->equalsKeyText('a', 'k', ['collation' => 'latin1_swedish_ci'], true));
        self::assertNull($dialect->equalsKeyText('a', 'k', ['collation' => 'utf8mb4_x; drop'], true));
    }

    /**
     * A value is inlined as MySQL reads it bound: null, an integer's digits, a
     * boolean as `1` or `0`, and UTF-8 text as a utf8mb4 string of its bytes;
     * anything else is not inlined.
     *
     * @return void
     */
    public function testAValueIsInlinedAsMySqlReadsItBound(): void
    {
        $dialect = new MySqlDialect;

        self::assertSame('NULL', $dialect->parameter(null));
        self::assertSame('1', $dialect->parameter(true));
        self::assertSame('0', $dialect->parameter(false));
        self::assertSame('42', $dialect->parameter(42));
        self::assertSame('(-42)', $dialect->parameter(-42));
        self::assertSame('_utf8mb4 X\'613f3f27625c00\'', $dialect->parameter("a??'b\\\0"));
        self::assertSame('_utf8mb4 X\'\'', $dialect->parameter(''));
        self::assertNull($dialect->parameter("\xff"));
        self::assertNull($dialect->parameter(1.5));
    }

    /**
     * Return a connection reporting the character sets.
     *
     * @param  array<string, string|null>  $sets
     * @return \Illuminate\Database\Connection
     */
    private static function connection(array $sets): Connection
    {
        $connection = \Mockery::mock(Connection::class);

        $connection->shouldReceive('selectOne')->andReturn((object) $sets);

        return $connection;
    }
}
