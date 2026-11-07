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
