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
     * The enum defines exactly the ten stages, in the order a decision runs
     * them (AUTHZ-7.1): subject, resource, tenant, deny, guardrail, boundary,
     * session, allow, administration, implicit.
     *
     * @return void
     */
    public function testExactlyTenCasesInRunOrder(): void
    {
        self::assertSame(
            [
                DecisionStage::SUBJECT,
                DecisionStage::RESOURCE,
                DecisionStage::TENANT,
                DecisionStage::DENY,
                DecisionStage::GUARDRAIL,
                DecisionStage::BOUNDARY,
                DecisionStage::SESSION,
                DecisionStage::ALLOW,
                DecisionStage::ADMINISTRATION,
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
        self::assertSame('tenant', DecisionStage::TENANT->value);
        self::assertSame('deny', DecisionStage::DENY->value);
        self::assertSame('guardrail', DecisionStage::GUARDRAIL->value);
        self::assertSame('boundary', DecisionStage::BOUNDARY->value);
        self::assertSame('session', DecisionStage::SESSION->value);
        self::assertSame('allow', DecisionStage::ALLOW->value);
        self::assertSame('administration', DecisionStage::ADMINISTRATION->value);
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
        self::assertSame(DecisionStage::TENANT, DecisionStage::tryFrom('tenant'));
        self::assertSame(DecisionStage::DENY, DecisionStage::tryFrom('deny'));
        self::assertSame(DecisionStage::GUARDRAIL, DecisionStage::tryFrom('guardrail'));
        self::assertSame(DecisionStage::BOUNDARY, DecisionStage::tryFrom('boundary'));
        self::assertSame(DecisionStage::SESSION, DecisionStage::tryFrom('session'));
        self::assertSame(DecisionStage::ADMINISTRATION, DecisionStage::tryFrom('administration'));
        self::assertSame(DecisionStage::ALLOW, DecisionStage::tryFrom('allow'));
        self::assertSame(DecisionStage::IMPLICIT, DecisionStage::tryFrom('implicit'));
        self::assertNull(DecisionStage::tryFrom('unknown'));
    }
}
