<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness;

/**
 * Unit tests for how long a decision that read an authentication requirement
 * may be reused: in its session, until its earliest met requirement lapses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementFreshness::class)]
final class RequirementFreshnessTest extends TestCase
{
    /**
     * Reset the frozen clock.
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
     * It keeps only the session's SHA-256 fingerprint, never the session id
     * itself, and no session stays none.
     *
     * @return void
     */
    public function testKeepsOnlyAFingerprintOfTheSession(): void
    {
        $freshness = new RequirementFreshness('session-1');

        self::assertSame(\hash('sha256', 'session-1'), $freshness->session);
        self::assertStringNotContainsString('session-1', \serialize($freshness));
        self::assertNull((new RequirementFreshness(null))->session);
        self::assertFalse($freshness->holdsFor(\hash('sha256', 'session-1')));
    }

    /**
     * It holds in its own session before the instant, and not at or after it.
     *
     * @return void
     */
    public function testHoldsBeforeTheInstantOnly(): void
    {
        $freshness = new RequirementFreshness('session-1', new \DateTimeImmutable('2026-11-06 12:00:00'));

        self::assertTrue($freshness->holdsFor('session-1', new \DateTimeImmutable('2026-11-06 11:59:59')));
        self::assertFalse($freshness->holdsFor('session-1', new \DateTimeImmutable('2026-11-06 12:00:00')));
        self::assertFalse($freshness->holdsFor('session-1', new \DateTimeImmutable('2026-11-06 12:00:01')));
    }

    /**
     * It never holds in another session, nor outside one.
     *
     * @return void
     */
    public function testNeverHoldsInAnotherSession(): void
    {
        $freshness = new RequirementFreshness('session-1', new \DateTimeImmutable('2026-11-06 12:00:00'));
        $before    = new \DateTimeImmutable('2026-11-06 11:00:00');

        self::assertFalse($freshness->holdsFor('session-2', $before));
        self::assertFalse($freshness->holdsFor(null, $before));
    }

    /**
     * Without an instant it holds for the whole of its session, and outside a
     * session only outside one.
     *
     * @return void
     */
    public function testWithoutAnInstantHoldsForItsSession(): void
    {
        $far = new \DateTimeImmutable('2100-01-01');

        self::assertTrue((new RequirementFreshness('session-1'))->holdsFor('session-1', $far));
        self::assertFalse((new RequirementFreshness('session-1'))->hasLapsed($far));
        self::assertTrue((new RequirementFreshness(null))->holdsFor(null, $far));
        self::assertFalse((new RequirementFreshness(null))->holdsFor('session-1', $far));
    }

    /**
     * Without an instant to judge at, it judges at now.
     *
     * @return void
     */
    public function testJudgesAtNowByDefault(): void
    {
        $freshness = new RequirementFreshness('session-1', new \DateTimeImmutable('2026-11-06 12:00:00'));

        Carbon::setTestNow('2026-11-06 11:59:59');

        self::assertTrue($freshness->holdsFor('session-1'));
        self::assertFalse($freshness->hasLapsed());

        Carbon::setTestNow('2026-11-06 12:00:00');

        self::assertFalse($freshness->holdsFor('session-1'));
        self::assertTrue($freshness->hasLapsed());
    }

    /**
     * The stricter of two is the one whose met requirement lapses first, the
     * first when neither lapses or both lapse at the same instant, the one
     * given when the other is absent, and none when neither is given.
     *
     * @return void
     */
    public function testTheStricterOfTwoLapsesFirst(): void
    {
        $noon  = new RequirementFreshness('session-1', new \DateTimeImmutable('2026-11-06 12:00:00'));
        $one   = new RequirementFreshness('session-1', new \DateTimeImmutable('2026-11-06 13:00:00'));
        $also  = new RequirementFreshness('session-1', new \DateTimeImmutable('2026-11-06 12:00:00'));
        $open  = new RequirementFreshness('session-1');
        $other = new RequirementFreshness('session-1');

        self::assertNull(RequirementFreshness::stricterOf(null, null));
        self::assertSame($noon, RequirementFreshness::stricterOf($noon, null));
        self::assertSame($noon, RequirementFreshness::stricterOf(null, $noon));
        self::assertSame($noon, RequirementFreshness::stricterOf($noon, $one));
        self::assertSame($noon, RequirementFreshness::stricterOf($one, $noon));
        self::assertSame($noon, RequirementFreshness::stricterOf($open, $noon));
        self::assertSame($noon, RequirementFreshness::stricterOf($noon, $open));
        self::assertSame($noon, RequirementFreshness::stricterOf($noon, $also));
        self::assertSame($open, RequirementFreshness::stricterOf($open, $other));
    }
}
