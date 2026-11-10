<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Reviews\Enums\UsageStatus;
use SineMacula\Laravel\Authorization\Reviews\RowUsage;

/**
 * Unit tests for what an access review knows of one row's use.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RowUsage::class)]
final class RowUsageTest extends TestCase
{
    /**
     * Its shape is its status, its last observed use and its coverage, each
     * instant in UTC, every one null when unknown.
     *
     * @return void
     */
    public function testItsShapeIsItsStatusLastUseAndCoverage(): void
    {
        $seen  = CarbonImmutable::create(2026, 11, 9, 11, 0, 0, 'Europe/Paris');
        $usage = new RowUsage(UsageStatus::USED, $seen, CarbonImmutable::create(2026, 11, 1, 0, 0, 0, 'UTC'), CarbonImmutable::create(2026, 11, 9, 12, 0, 0, 'UTC'));

        self::assertSame(
            ['status' => 'used', 'last_observed_at' => '2026-11-09T10:00:00Z', 'coverage_from' => '2026-11-01T00:00:00Z', 'coverage_until' => '2026-11-09T12:00:00Z'],
            $usage->toArray(),
        );
        self::assertSame(['status' => 'unknown', 'last_observed_at' => null, 'coverage_from' => null, 'coverage_until' => null], RowUsage::unknown()->toArray());
    }
}
