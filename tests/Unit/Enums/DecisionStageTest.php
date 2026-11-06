<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;

/**
 * Unit tests for the decision-stage enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(DecisionStage::class)]
final class DecisionStageTest extends TestCase
{
    /**
     * The enum defines exactly the five stages, in the order a decision runs
     * them: subject, resource, deny, allow, implicit.
     *
     * @return void
     */
    public function testExactlyFiveCasesInRunOrder(): void
    {
        self::assertSame(
            [
                DecisionStage::SUBJECT,
                DecisionStage::RESOURCE,
                DecisionStage::DENY,
                DecisionStage::ALLOW,
                DecisionStage::IMPLICIT,
            ],
            DecisionStage::cases(),
        );
    }

    /**
     * Every case carries its documented backing value.
     *
     * @return void
     */
    public function testBackingValues(): void
    {
        self::assertSame('subject', DecisionStage::SUBJECT->value);
        self::assertSame('resource', DecisionStage::RESOURCE->value);
        self::assertSame('deny', DecisionStage::DENY->value);
        self::assertSame('allow', DecisionStage::ALLOW->value);
        self::assertSame('implicit', DecisionStage::IMPLICIT->value);
    }

    /**
     * tryFrom() resolves every known backing value and returns null for an
     * unknown one.
     *
     * @return void
     */
    public function testTryFromResolvesKnownValues(): void
    {
        self::assertSame(DecisionStage::SUBJECT, DecisionStage::tryFrom('subject'));
        self::assertSame(DecisionStage::RESOURCE, DecisionStage::tryFrom('resource'));
        self::assertSame(DecisionStage::DENY, DecisionStage::tryFrom('deny'));
        self::assertSame(DecisionStage::ALLOW, DecisionStage::tryFrom('allow'));
        self::assertSame(DecisionStage::IMPLICIT, DecisionStage::tryFrom('implicit'));
        self::assertNull(DecisionStage::tryFrom('unknown'));
    }
}
