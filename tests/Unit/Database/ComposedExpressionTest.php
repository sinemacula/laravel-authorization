<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Database\ComposedExpression;
use Tests\Concerns\CompilesQueries;

/**
 * Unit tests for a raw clause composed from wrapped identifiers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ComposedExpression::class)]
final class ComposedExpressionTest extends TestCase
{
    use CompilesQueries;

    /**
     * The SQL is compiled as composed on every grammar, its placeholders left
     * for the values bound.
     *
     * @return void
     */
    public function testTheSqlIsCompiledAsComposed(): void
    {
        foreach (self::drivers() as $driver) {
            $guard = self::wrappedOn($driver, 'roles.guard');
            $query = self::queryOn($driver, 'roles')->whereRaw(new ComposedExpression("{$guard} is null or {$guard} = ?"), ['web']);

            self::assertStringEndsWith("where {$guard} is null or {$guard} = ?", $query->toSql(), $driver);
            self::assertSame(['web'], $query->getBindings(), $driver);
        }
    }
}
