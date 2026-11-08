<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Enums\WideningReason;

/**
 * Unit tests for `WideningReason`, why a proposed grant widens an identity's
 * scope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(WideningReason::class)]
final class WideningReasonTest extends TestCase
{
    /**
     * The reasons and their values are stable, in declared order.
     *
     * @return void
     */
    public function testTheReasonsAreStable(): void
    {
        self::assertSame(
            ['identity', 'platform', 'new_tenant', 'new_subtree', 'incomplete_directory', 'unreadable_tree', 'membership'],
            \array_map(static fn (WideningReason $reason): string => $reason->value, WideningReason::cases()),
        );
    }
}
