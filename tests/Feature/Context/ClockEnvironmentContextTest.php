<?php

declare(strict_types = 1);

namespace Tests\Feature\Context;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Date;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Context\ClockEnvironmentContext;
use SineMacula\Laravel\Authorization\Contracts\EnvironmentContext;
use Tests\TestCase;

/**
 * Feature coverage for `ClockEnvironmentContext`, the default environment
 * context, which supplies the current time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClockEnvironmentContext::class)]
final class ClockEnvironmentContextTest extends TestCase
{
    /**
     * The time is Laravel's `now()`, in UTC as ISO 8601 to the second, whatever
     * the zone the clock is in.
     *
     * @return void
     */
    public function testTheTimeIsNowInUtc(): void
    {
        $this->travelTo(Carbon::parse('2026-01-31 10:30:15.750', 'Europe/Paris'));

        $context = new ClockEnvironmentContext;

        self::assertInstanceOf(EnvironmentContext::class, $context);
        self::assertSame(['time' => '2026-01-31T09:30:15Z'], $context->values());
        self::assertSame('2026-01-31T09:30:15Z', Date::now()->utc()->format(ClockEnvironmentContext::TIME_FORMAT));
    }

    /**
     * The time follows the clock, so a test travelling in time decides as of
     * that time.
     *
     * @return void
     */
    public function testTheTimeFollowsTheClock(): void
    {
        $context = new ClockEnvironmentContext;

        $this->travelTo(Carbon::parse('2026-06-01T00:00:00Z'));
        self::assertSame(['time' => '2026-06-01T00:00:00Z'], $context->values());

        $this->travel(90)->seconds();
        self::assertSame(['time' => '2026-06-01T00:01:30Z'], $context->values());
    }
}
