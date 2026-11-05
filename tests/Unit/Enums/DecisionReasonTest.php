<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;

/**
 * Unit tests for the decision-reason enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(DecisionReason::class)]
final class DecisionReasonTest extends TestCase
{
    /**
     * Every case carries a non-empty backing value.
     *
     * @return void
     */
    public function testEveryBackingValueIsNonEmpty(): void
    {
        foreach (DecisionReason::cases() as $case) {
            self::assertNotSame('', $case->value, "Case {$case->name} has an empty backing value.");
        }
    }

    /**
     * The case count matches the four-step evaluation model plus the
     * invalid-policy and inactive-subject denials.
     *
     * @return void
     */
    public function testExactlySixCases(): void
    {
        self::assertCount(6, DecisionReason::cases());
    }

    /**
     * The invalid-policy case is backed by its stable audit-log value.
     *
     * @return void
     */
    public function testInvalidPolicyBackingValue(): void
    {
        self::assertSame('invalid_policy', DecisionReason::INVALID_POLICY->value);
    }

    /**
     * label() returns the exact human-readable text for every case.
     *
     * @return void
     */
    public function testLabelReturnsExactTextForEachCase(): void
    {
        self::assertSame('explicit allow from a policy statement', DecisionReason::EXPLICIT_ALLOW->label());
        self::assertSame('explicit deny from a policy statement', DecisionReason::EXPLICIT_DENY->label());
        self::assertSame('implicit deny (no statement matched)', DecisionReason::IMPLICIT_DENY->label());
        self::assertSame('RBAC grant (direct permission or role-inherited)', DecisionReason::RBAC_ALLOW->label());
        self::assertSame('invalid policy (a policy could not be evaluated)', DecisionReason::INVALID_POLICY->label());
        self::assertSame('subject inactive (the subject or its identity is inactive)', DecisionReason::SUBJECT_INACTIVE->label());
    }

    /**
     * label() returns a non-empty string for every case.
     *
     * @return void
     */
    public function testLabelReturnsNonEmptyStringForEachCase(): void
    {
        foreach (DecisionReason::cases() as $case) {
            self::assertNotSame('', $case->label(), "Case {$case->name} returned an empty label.");
        }
    }

    /**
     * tryFrom() resolves every known backing value.
     *
     * @return void
     */
    public function testTryFromResolvesKnownValues(): void
    {
        self::assertSame(DecisionReason::EXPLICIT_ALLOW, DecisionReason::tryFrom('explicit_allow'));
        self::assertSame(DecisionReason::EXPLICIT_DENY, DecisionReason::tryFrom('explicit_deny'));
        self::assertSame(DecisionReason::IMPLICIT_DENY, DecisionReason::tryFrom('implicit_deny'));
        self::assertSame(DecisionReason::RBAC_ALLOW, DecisionReason::tryFrom('rbac_allow'));
        self::assertSame(DecisionReason::INVALID_POLICY, DecisionReason::tryFrom('invalid_policy'));
        self::assertSame(DecisionReason::SUBJECT_INACTIVE, DecisionReason::tryFrom('subject_inactive'));
    }

    /**
     * tryFrom() returns null for unknown values.
     *
     * @return void
     */
    public function testTryFromReturnsNullForUnknownValue(): void
    {
        self::assertNull(DecisionReason::tryFrom('unknown'));
    }
}
