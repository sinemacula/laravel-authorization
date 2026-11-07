<?php

declare(strict_types = 1);

namespace Tests\Unit\Query\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;

/**
 * Unit tests for the kinds of column a query scope compares.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ColumnKind::class)]
final class ColumnKindTest extends TestCase
{
    /**
     * The kinds are an integer, a string and a uuid.
     *
     * @return void
     */
    public function testTheKindsAreAnIntegerAStringAndAUuid(): void
    {
        self::assertSame(['integer', 'string', 'uuid'], \array_map(static fn (ColumnKind $kind): string => $kind->value, ColumnKind::cases()));
    }
}
