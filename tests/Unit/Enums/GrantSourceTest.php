<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\GrantSource;

/**
 * Unit tests for the grant-source enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantSource::class)]
final class GrantSourceTest extends TestCase
{
    /**
     * The enum defines exactly its eight sources, each with its documented
     * backing value, in declaration order.
     *
     * @return void
     */
    public function testCasesAndBackingValues(): void
    {
        self::assertSame(
            ['permission', 'role_permission', 'policy', 'role_policy', 'break_glass_permission', 'break_glass_policy', 'resource_policy', 'unavailable'],
            \array_map(static fn (GrantSource $source): string => $source->value, GrantSource::cases()),
        );
    }
}
