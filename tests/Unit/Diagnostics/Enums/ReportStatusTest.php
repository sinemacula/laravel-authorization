<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\ReportStatus;

/**
 * Unit tests for the outcome of the configuration report and the exit code it
 * gives.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReportStatus::class)]
final class ReportStatusTest extends TestCase
{
    /**
     * Passed exits 0, refused 1 and incomplete 3; 2 is left to a bad
     * invocation.
     *
     * @return void
     */
    public function testEachStatusGivesItsExitCode(): void
    {
        self::assertSame(0, ReportStatus::PASSED->exitCode());
        self::assertSame(1, ReportStatus::REFUSED->exitCode());
        self::assertSame(3, ReportStatus::INCOMPLETE->exitCode());
        self::assertSame(['passed', 'refused', 'incomplete'], \array_column(ReportStatus::cases(), 'value'));
    }
}
