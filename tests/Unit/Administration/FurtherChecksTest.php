<?php

declare(strict_types = 1);

namespace Tests\Unit\Administration;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * Unit tests for `FurtherChecks`, what the administration stage may ask of the
 * decision pipeline.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FurtherChecks::class)]
final class FurtherChecksTest extends TestCase
{
    /**
     * The checks carry the subject, decide each further check through the
     * pipeline's callback, on the resource given or none, and gather each
     * check's sources through the other; with no tenant given, the check is
     * made from the platform.
     *
     * @return void
     */
    public function testItAsksThePipeline(): void
    {
        $subject  = new Subject(new \stdClass);
        $decision = Decision::allow(DecisionStage::ALLOW);
        $resource = ResourceReference::record('post', '1');
        $asked    = [];
        $checks   = new FurtherChecks(
            $subject,
            static function (string $action, ?ResourceReference $on) use (&$asked, $decision): Decision {
                $asked[] = [$action, $on];

                return $decision;
            },
            static function (string $action) use (&$asked): null {
                $asked[] = [$action];

                return null;
            },
        );

        self::assertSame($subject, $checks->subject);
        self::assertSame($decision, $checks->decide('posts:edit', $resource));
        self::assertSame($decision, $checks->decide('posts:read'));
        self::assertNull($checks->sources('posts:edit'));
        self::assertSame([['posts:edit', $resource], ['posts:read', null], ['posts:edit']], $asked);
        self::assertNull($checks->from);
    }

    /**
     * The checks carry the tenant the check is made from, for the owner rule.
     *
     * @return void
     */
    public function testItCarriesTheTenantTheCheckIsMadeFrom(): void
    {
        $tenant = new Reference('tenant', 'a');
        $checks = new FurtherChecks(new Subject(new \stdClass), static fn (): Decision => Decision::allow(DecisionStage::ALLOW), static fn (): null => null, $tenant);

        self::assertSame($tenant, $checks->from);
    }

    /**
     * The sources the pipeline gathers for a further check are handed back as
     * they are.
     *
     * @return void
     */
    public function testItHandsBackTheSourcesThePipelineGathers(): void
    {
        $sources = new CheckSources([], null, [], new CheckContext, static fn (): ?string => null, new SessionCaps);
        $checks  = new FurtherChecks(new Subject(new \stdClass), static fn (): Decision => Decision::allow(DecisionStage::ALLOW), static fn (): CheckSources => $sources);

        self::assertSame($sources, $checks->sources('posts:edit'));
    }

    /**
     * Every authentication requirement a further check read is kept, and
     * carried into the decision the stage returns, which then names its own and
     * theirs, once each, sorted, and may be reused no longer than the earliest
     * of them stays met; before any further check read one, the decision is
     * carried as it is.
     *
     * @return void
     */
    public function testItCarriesTheRequirementsItsChecksRead(): void
    {
        $one     = new RequirementFreshness('session-1', new \DateTimeImmutable('2026-11-06 13:00:00'));
        $noon    = new RequirementFreshness('session-1', new \DateTimeImmutable('2026-11-06 12:00:00'));
        $early   = new RequirementFreshness('session-1', new \DateTimeImmutable('2026-11-06 11:00:00'));
        $further = [
            'posts:edit'   => Decision::allow(DecisionStage::ALLOW)->withFreshness($one, ['multifactor']),
            'posts:delete' => Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT)->withFreshness($noon, ['phishing_resistant']),
            'posts:read'   => Decision::allow(DecisionStage::ALLOW),
        ];
        $checks = new FurtherChecks(new Subject(new \stdClass), static fn (string $action): Decision => $further[$action], static fn (): null => null);
        $plain  = Decision::allow(DecisionStage::ALLOW);

        self::assertSame($plain, $checks->carriedInto($plain));

        foreach (\array_keys($further) as $action) {
            $checks->decide($action);
        }

        $carried = $checks->carriedInto($plain);
        $own     = $checks->carriedInto(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT)->withFreshness($early, ['multifactor', 'biometric']));

        self::assertTrue($carried->isAllowed());
        self::assertSame(['multifactor', 'phishing_resistant'], $carried->requirementsRead);
        self::assertSame($noon, $carried->freshness);
        self::assertFalse($own->isAllowed());
        self::assertSame(['biometric', 'multifactor', 'phishing_resistant'], $own->requirementsRead);
        self::assertSame($early, $own->freshness);
    }
}
