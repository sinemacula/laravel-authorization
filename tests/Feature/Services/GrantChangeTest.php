<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Services\Support\GrantChange;
use Tests\TestCase;

/**
 * Feature tests for `GrantChange`: which writes may widen what a grantee holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantChange::class)]
final class GrantChangeTest extends TestCase
{
    /**
     * A new or re-armed grant widens; one left as it was, replaced or revoked
     * does not; a changed reach widens only below its tenant.
     *
     * @return void
     */
    public function testANewGrantAndAWiderReachWiden(): void
    {
        self::assertTrue((new GrantChange(GrantOutcome::GRANTED))->isWidening(null, false));
        self::assertTrue((new GrantChange(GrantOutcome::REARMED, Carbon::parse('2026-07-01')))->isWidening(Carbon::parse('2026-06-01'), false));
        self::assertTrue((new GrantChange(GrantOutcome::REACH_CHANGED))->isWidening(null, true));
        self::assertFalse((new GrantChange(GrantOutcome::REACH_CHANGED))->isWidening(null, false));
        self::assertFalse((new GrantChange(GrantOutcome::UNCHANGED))->isWidening(null, true));
        self::assertFalse((new GrantChange(GrantOutcome::REPLACED))->isWidening(null, true));
    }

    /**
     * A changed expiry widens when it ends later or never, or reaches below a
     * tenant the row did not reach below, or may not have; a shorter one kept
     * within the reach it had does not.
     *
     * @return void
     */
    public function testAChangedExpiryWidensWhenLaterOrReachingFurther(): void
    {
        $day  = Carbon::parse('2026-07-02 12:00:00');
        $week = Carbon::parse('2026-07-08 12:00:00');

        $limited = new GrantChange(GrantOutcome::EXPIRY_CHANGED, $day, false);
        $below   = new GrantChange(GrantOutcome::EXPIRY_CHANGED, $week, true);
        $unread  = new GrantChange(GrantOutcome::EXPIRY_CHANGED, $week);
        $forever = new GrantChange(GrantOutcome::EXPIRY_CHANGED, null, true);

        self::assertTrue($limited->isWidening($week, false));
        self::assertTrue($limited->isWidening(null, false));
        self::assertFalse($limited->isWidening($day, false));
        self::assertTrue($limited->isWidening($day, true));
        self::assertFalse($below->isWidening($day, true));
        self::assertFalse($below->isWidening($week, true));
        self::assertTrue($unread->isWidening($day, true));
        self::assertFalse($unread->isWidening($day, false));
        self::assertFalse($forever->isWidening($day, true));
    }
}
