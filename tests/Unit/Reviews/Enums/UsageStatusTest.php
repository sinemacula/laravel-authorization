<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Reviews\Enums\UsageStatus;

/**
 * Unit tests for what an access review knows of a route's use.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UsageStatus::class)]
final class UsageStatusTest extends TestCase
{
    /**
     * The cases are backed by stable strings.
     *
     * @return void
     */
    public function testCasesAreBackedByStableStrings(): void
    {
        self::assertSame(['used', 'unused', 'unknown'], \array_map(static fn (UsageStatus $case): string => $case->value, UsageStatus::cases()));
    }
}
