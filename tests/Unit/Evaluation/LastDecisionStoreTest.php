<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the single slot holding the last decision and its provenance,
 * which never hands back a decision whose authentication requirement has
 * stopped being met.
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

        $store->put($first, new DecisionProvenance);
        $store->put($last, new DecisionProvenance);

        self::assertSame($last, $store->get());

        $store->forget();

        self::assertNull($store->get());

        $store->put($first, new DecisionProvenance);
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

        $store->put($decision, new DecisionProvenance);

        Carbon::setTestNow('2026-11-06 11:59:59');

        self::assertSame($decision, $store->get());

        Carbon::setTestNow('2026-11-06 12:00:00');

        self::assertNull($store->get());
    }

    /**
     * A decision whose requirement gives no instant is handed back, whatever
     * session asks; the session is the reader's to check, with
     * `wasRecordedIn()`.
     *
     * @return void
     */
    public function testKeepsADecisionWithoutAnInstant(): void
    {
        $store    = new LastDecisionStore;
        $decision = Decision::allow(DecisionStage::ALLOW)->withFreshness(new RequirementFreshness('session-1'));

        $store->put($decision, new DecisionProvenance);

        self::assertSame($decision, $store->get());
    }

    /**
     * The store remembers the session of the request that put the last
     * decision, none by default, and forgets it with the decision.
     *
     * @return void
     */
    public function testRemembersTheSessionTheDecisionWasRecordedIn(): void
    {
        $store    = new LastDecisionStore;
        $decision = Decision::allow(DecisionStage::ALLOW);

        self::assertTrue($store->wasRecordedIn(null));

        $store->put($decision, new DecisionProvenance, 'session-1');

        self::assertTrue($store->wasRecordedIn('session-1'));
        self::assertFalse($store->wasRecordedIn('session-2'));
        self::assertFalse($store->wasRecordedIn(null));

        $store->put($decision, new DecisionProvenance);

        self::assertTrue($store->wasRecordedIn(null));
        self::assertFalse($store->wasRecordedIn('session-1'));

        $store->put($decision, new DecisionProvenance, 'session-1');
        $store->forget();

        self::assertTrue($store->wasRecordedIn(null));
    }

    /**
     * The store keeps the provenance of the last decision put, replaced by the
     * next put, and forgets it with the decision; none before any is put.
     *
     * @return void
     */
    public function testKeepsTheProvenanceOfTheLastDecision(): void
    {
        $store    = new LastDecisionStore;
        $decision = Decision::allow(DecisionStage::ALLOW);
        $first    = new DecisionProvenance(new Reference('user', '1'));
        $last     = new DecisionProvenance(new Reference('user', '2'));

        self::assertNull($store->provenance());

        $store->put($decision, $first);
        $store->put($decision, $last);

        self::assertSame($last, $store->provenance());

        $store->forget();

        self::assertNull($store->provenance());

        $store->put($decision, $first);
        $store->reset();

        self::assertNull($store->provenance());
    }

    /**
     * The provenance of a decision is the one it was put with while it is the
     * last decision put, and none once another replaced it, or for one never
     * put.
     *
     * @return void
     */
    public function testGivesTheProvenanceOfTheDecisionOnlyWhileItIsTheLast(): void
    {
        $store      = new LastDecisionStore;
        $decision   = Decision::allow(DecisionStage::ALLOW);
        $later      = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
        $provenance = new DecisionProvenance(new Reference('user', '1'));

        self::assertNull($store->provenanceOf($decision));

        $store->put($decision, $provenance);

        self::assertSame($provenance, $store->provenanceOf($decision));
        self::assertNull($store->provenanceOf(Decision::allow(DecisionStage::ALLOW)));

        $store->put($later, new DecisionProvenance(new Reference('user', '2')));

        self::assertNull($store->provenanceOf($decision));
    }

    /**
     * The provenance is that of the decision last put, even once the store no
     * longer hands the decision back, so a reader asks for the decision first.
     *
     * @return void
     */
    public function testKeepsTheProvenanceOfALapsedDecision(): void
    {
        $store      = new LastDecisionStore;
        $provenance = new DecisionProvenance(new Reference('user', '1'));

        $store->put(Decision::allow(DecisionStage::ALLOW)->withFreshness(new RequirementFreshness('session-1', new \DateTimeImmutable('2026-11-06 12:00:00'))), $provenance);

        Carbon::setTestNow('2026-11-06 12:00:00');

        self::assertNull($store->get());
        self::assertSame($provenance, $store->provenance());
    }
}
