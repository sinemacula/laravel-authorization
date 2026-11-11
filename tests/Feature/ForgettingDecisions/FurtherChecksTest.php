<?php

declare(strict_types = 1);

namespace Tests\Feature\ForgettingDecisions;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionMemory;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Subject;
use Tests\TestCase;

/**
 * Feature tests for the further checks of one decision when the decisions of
 * the request are forgotten while it is made (N112): whether a right is
 * limited, worked out once for each right until then, is worked out again, and
 * once only.
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
     * A right found limited is remembered for the decision until the decisions
     * are forgotten, then worked out again and remembered from then on.
     *
     * @return void
     */
    public function testWhatLimitsARightIsWorkedOutAgainOnceTheDecisionsAreForgotten(): void
    {
        $checks   = new FurtherChecks(new Subject(new \stdClass), static fn (): Decision => Decision::allow(DecisionStage::ALLOW), static fn (): null => null);
        $workings = 0;
        $limit    = static function () use (&$workings): bool {
            return ++$workings === 1;
        };

        self::assertTrue($checks->limited('roles:assign', $limit));
        self::assertTrue($checks->limited('roles:assign', $limit));

        DecisionMemory::current()->forget(new LastDecisionStore);

        self::assertFalse($checks->limited('roles:assign', $limit));
        self::assertFalse($checks->limited('roles:assign', $limit));
        self::assertSame(2, $workings);
    }

    /**
     * Each right keeps its own answer for the decision: two keys asked in turn
     * are each worked out once, and each answers what its own callback found.
     *
     * @return void
     */
    public function testEachRightKeepsItsOwnAnswer(): void
    {
        $checks   = new FurtherChecks(new Subject(new \stdClass), static fn (): Decision => Decision::allow(DecisionStage::ALLOW), static fn (): null => null);
        $workings = ['roles:assign' => 0, 'roles:revoke' => 0];
        $limit    = static function (string $key, bool $isLimited) use (&$workings): \Closure {
            return static function () use ($key, $isLimited, &$workings): bool {
                $workings[$key]++;

                return $isLimited;
            };
        };

        $assign = $limit('roles:assign', true);
        $revoke = $limit('roles:revoke', false);

        self::assertTrue($checks->limited('roles:assign', $assign));
        self::assertFalse($checks->limited('roles:revoke', $revoke));
        self::assertTrue($checks->limited('roles:assign', $assign));
        self::assertFalse($checks->limited('roles:revoke', $revoke));

        self::assertSame(['roles:assign' => 1, 'roles:revoke' => 1], $workings);
    }
}
