<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness;

/**
 * Unit tests for the single slot holding the last decision, which never hands
 * back a decision whose authentication requirement has stopped being met.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LastDecisionStore::class)]
final class LastDecisionStoreTest extends TestCase
{
    /**
     * Release the clock.
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
     * The store holds the last decision put, until it is forgotten or reset.
     *
     * @return void
     */
    public function testHoldsTheLastDecision(): void
    {
        $store = new LastDecisionStore;
        $first = Decision::allow(DecisionStage::ALLOW);
        $last  = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);

        self::assertNull($store->get());

        $store->put($first);
        $store->put($last);

        self::assertSame($last, $store->get());

        $store->forget();

        self::assertNull($store->get());

        $store->put($first);
        $store->reset();

        self::assertNull($store->get());
    }

    /**
     * A decision that read a met requirement is handed back until the
     * requirement stops being met, and never after.
     *
     * @return void
     */
    public function testDropsADecisionPastItsMetUntil(): void
    {
        $store    = new LastDecisionStore;
        $decision = Decision::allow(DecisionStage::ALLOW)->withFreshness(new RequirementFreshness('session-1', new \DateTimeImmutable('2026-11-06 12:00:00')));

        $store->put($decision);

        Carbon::setTestNow('2026-11-06 11:59:59');

        self::assertSame($decision, $store->get());

        Carbon::setTestNow('2026-11-06 12:00:00');

        self::assertNull($store->get());
    }

    /**
     * A decision whose requirement gives no instant is handed back, whatever
     * session asks; the session is the reader's to check.
     *
     * @return void
     */
    public function testKeepsADecisionWithoutAnInstant(): void
    {
        $store    = new LastDecisionStore;
        $decision = Decision::allow(DecisionStage::ALLOW)->withFreshness(new RequirementFreshness('session-1'));

        $store->put($decision);

        self::assertSame($decision, $store->get());
    }
}
