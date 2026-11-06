<?php

declare(strict_types = 1);

namespace Tests\Unit\Query\Contracts;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Query\Contracts\Dialect;
use SineMacula\Laravel\Authorization\Query\Dialects\MySqlDialect;
use SineMacula\Laravel\Authorization\Query\Dialects\PostgresDialect;
use SineMacula\Laravel\Authorization\Query\Dialects\SqliteDialect;

/**
 * Unit tests for the contract of the SQL a query scope writes on one database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class DialectTest extends TestCase
{
    /**
     * Every supported database's dialect writes each fragment the contract
     * declares.
     *
     * @return void
     */
    public function testEveryDialectWritesEachFragment(): void
    {
        $methods = \array_map(static fn (\ReflectionMethod $method): string => $method->getName(), (new \ReflectionClass(Dialect::class))->getMethods());

        self::assertSame(['kindOf', 'isUtf8', 'keyGuard', 'keyLength', 'equalsBytes'], $methods);

        foreach ([SqliteDialect::class, PostgresDialect::class, MySqlDialect::class] as $dialect) {
            self::assertContains(Dialect::class, \class_implements($dialect), $dialect);
        }
    }
}
