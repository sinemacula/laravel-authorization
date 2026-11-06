<?php

declare(strict_types = 1);

namespace Tests\Unit\Query\Dialects;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Query\Dialects\Dialects;
use SineMacula\Laravel\Authorization\Query\Dialects\MySqlDialect;
use SineMacula\Laravel\Authorization\Query\Dialects\PostgresDialect;
use SineMacula\Laravel\Authorization\Query\Dialects\SqliteDialect;

/**
 * Unit tests for the dialect each driver is written in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Dialects::class)]
final class DialectsTest extends TestCase
{
    /**
     * SQLite, PostgreSQL and MySQL each have a dialect; any other driver,
     * MariaDB's included, has none.
     *
     * @return void
     */
    public function testEachSupportedDriverHasADialect(): void
    {
        self::assertInstanceOf(SqliteDialect::class, Dialects::for('sqlite'));
        self::assertInstanceOf(PostgresDialect::class, Dialects::for('pgsql'));
        self::assertInstanceOf(MySqlDialect::class, Dialects::for('mysql'));
        self::assertNull(Dialects::for('mariadb'));
        self::assertNull(Dialects::for('sqlsrv'));
    }
}
