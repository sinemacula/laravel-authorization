<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\BootCheckOutcome;

/**
 * Unit tests for what became of a check the diagnostic boot runs by building
 * what the configuration names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BootCheckOutcome::class)]
final class BootCheckOutcomeTest extends TestCase
{
    /**
     * The outcomes may be shown by the report, so they never change.
     *
     * @return void
     */
    public function testTheOutcomesAreStable(): void
    {
        self::assertSame(['passed', 'failed', 'not_run'], \array_column(BootCheckOutcome::cases(), 'value'));
    }
}
