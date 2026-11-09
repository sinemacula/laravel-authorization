<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews\Support;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewPosition;

/**
 * Unit tests for where a paged review stands.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReviewPosition::class)]
final class ReviewPositionTest extends TestCase
{
    /**
     * A review begins now, in UTC, before its first row, and each position
     * after a row keeps the review's instant.
     *
     * @return void
     */
    public function testAPositionKeepsTheReviewsInstant(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2030-01-01 05:00:00.5', 'Europe/Paris'));

        $start = ReviewPosition::start();

        CarbonImmutable::setTestNow();

        self::assertSame(['2030-01-01 04:00:00.500000', 'UTC', null], [$start->at->format('Y-m-d H:i:s.u'), $start->at->getTimezone()->getName(), $start->after]);

        $next = $start->after([1, 'a', null, true]);

        self::assertSame($start->at, $next->at);
        self::assertSame([1, 'a', null, true], $next->after);
        self::assertNull($start->after);
    }
}
