<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Support\GrantExpiry;

/**
 * Unit tests for the seconds until the nearest of a set of grant expiries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantExpiry::class)]
final class GrantExpiryTest extends TestCase
{
    /**
     * Start the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-07-01 12:00:00');
    }

    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * The nearest expiry wins, whether given as the column's text or as an
     * instant in any zone, and grants that never expire are skipped.
     *
     * @return void
     */
    public function testTheNearestExpiryWins(): void
    {
        $instant = new \DateTimeImmutable('2026-07-01 14:02:00', new \DateTimeZone('+02:00'));

        self::assertSame(120, GrantExpiry::nearest(null, ['2026-07-01 12:05:00', null, $instant, '']));
        self::assertSame(300, GrantExpiry::nearest(null, ['2026-07-01 12:05:00']));
    }

    /**
     * An expiry already known is kept when it is nearer, and replaced when one
     * of the expiries is.
     *
     * @return void
     */
    public function testAKnownExpiryIsKeptOnlyWhenNearer(): void
    {
        self::assertSame(60, GrantExpiry::nearest(60, ['2026-07-01 12:05:00']));
        self::assertSame(300, GrantExpiry::nearest(600, ['2026-07-01 12:05:00']));
        self::assertSame(60, GrantExpiry::nearest(60, []));
    }

    /**
     * Without any expiry nothing expires.
     *
     * @return void
     */
    public function testWithoutAnExpiryNothingExpires(): void
    {
        self::assertNull(GrantExpiry::nearest(null, [null, null]));
        self::assertNull(GrantExpiry::nearest(null, []));
    }
}
