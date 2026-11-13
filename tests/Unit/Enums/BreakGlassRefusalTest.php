<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Enums\BreakGlassRefusal;

/**
 * Unit tests for `BreakGlassRefusal`, why a break-glass call was refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BreakGlassRefusal::class)]
final class BreakGlassRefusalTest extends TestCase
{
    /**
     * The reasons and their values are stable, in declared order.
     *
     * @return void
     */
    public function testTheReasonsAreStable(): void
    {
        self::assertSame(
            ['disabled', 'not_human', 'not_listed', 'duration', 'justification', 'note_refused', 'note_too_long', 'half_tenant', 'not_grantee'],
            \array_map(static fn (BreakGlassRefusal $reason): string => $reason->value, BreakGlassRefusal::cases()),
        );
    }
}
