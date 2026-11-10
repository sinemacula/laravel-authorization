<?php

declare(strict_types = 1);

namespace Tests\Unit\Usage;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Usage\CoveragePeriod;

/**
 * Unit tests for a period grant usage tracking was on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CoveragePeriod::class)]
final class CoveragePeriodTest extends TestCase
{
    /**
     * A period keeps its start and its end.
     *
     * @return void
     */
    public function testAPeriodKeepsItsBounds(): void
    {
        $from   = CarbonImmutable::parse('2026-11-09 08:00:00');
        $until  = CarbonImmutable::parse('2026-11-09 10:00:00');
        $period = new CoveragePeriod($from, $until);

        self::assertSame([$from, $until], [$period->from, $period->until]);
    }
}
