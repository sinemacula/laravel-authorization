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
     * The enum defines exactly the eight denial reasons, in declaration order:
     * an allowed check carries no reason, so there is no allow case.
     *
     * @return void
     */
    public function testExactlyEightCases(): void
    {
        self::assertSame(
            [
                DecisionReason::EXPLICIT_DENY,
                DecisionReason::NO_MATCH,
                DecisionReason::CONDITION_FAILED,
                DecisionReason::INVALID_POLICY,
                DecisionReason::SUBJECT_INACTIVE,
                DecisionReason::SUBJECT_UNRESOLVED,
                DecisionReason::RESOURCE_UNRESOLVED,
                DecisionReason::TENANT_SCOPE,
            ],
            DecisionReason::cases(),
        );
    }

    /**
     * Every case is backed by its stable audit-log code.
     *
     * @return void
     */
    public function testBackingValues(): void
    {
        self::assertSame('explicit_deny', DecisionReason::EXPLICIT_DENY->value);
        self::assertSame('no_match', DecisionReason::NO_MATCH->value);
        self::assertSame('condition_failed', DecisionReason::CONDITION_FAILED->value);
        self::assertSame('invalid_policy', DecisionReason::INVALID_POLICY->value);
        self::assertSame('subject_inactive', DecisionReason::SUBJECT_INACTIVE->value);
        self::assertSame('subject_unresolved', DecisionReason::SUBJECT_UNRESOLVED->value);
        self::assertSame('resource_unresolved', DecisionReason::RESOURCE_UNRESOLVED->value);
        self::assertSame('tenant_scope', DecisionReason::TENANT_SCOPE->value);
    }

    /**
     * Every code keeps to the reason grammar: 1 to 64 characters of lower-case
     * letters, digits, `_`, `.`, `:` and `-`, starting with a letter or digit.
     *
     * @return void
     */
    public function testEveryCodeKeepsToTheGrammar(): void
    {
        foreach (DecisionReason::cases() as $case) {
            self::assertMatchesRegularExpression('/^[a-z0-9][a-z0-9_.:-]{0,63}$/', $case->value, "Case {$case->name} breaks the reason grammar.");
        }
    }

    /**
     * label() returns the exact human-readable text for every case.
     *
     * @return void
     */
    public function testLabelReturnsExactTextForEachCase(): void
    {
        self::assertSame('an applicable statement denies it', DecisionReason::EXPLICIT_DENY->label());
        self::assertSame('no statement or permission names it', DecisionReason::NO_MATCH->label());
        self::assertSame('a statement names it, but its conditions do not hold', DecisionReason::CONDITION_FAILED->label());
        self::assertSame('an applicable policy cannot be evaluated', DecisionReason::INVALID_POLICY->label());
        self::assertSame('the subject or its identity is inactive', DecisionReason::SUBJECT_INACTIVE->label());
        self::assertSame('there is no subject', DecisionReason::SUBJECT_UNRESOLVED->label());
        self::assertSame('the resource cannot be identified', DecisionReason::RESOURCE_UNRESOLVED->label());
        self::assertSame('the resource belongs to a tenant outside the scope', DecisionReason::TENANT_SCOPE->label());
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
        self::assertSame(DecisionReason::EXPLICIT_DENY, DecisionReason::tryFrom('explicit_deny'));
        self::assertSame(DecisionReason::NO_MATCH, DecisionReason::tryFrom('no_match'));
        self::assertSame(DecisionReason::CONDITION_FAILED, DecisionReason::tryFrom('condition_failed'));
        self::assertSame(DecisionReason::INVALID_POLICY, DecisionReason::tryFrom('invalid_policy'));
        self::assertSame(DecisionReason::SUBJECT_INACTIVE, DecisionReason::tryFrom('subject_inactive'));
        self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, DecisionReason::tryFrom('subject_unresolved'));
        self::assertSame(DecisionReason::RESOURCE_UNRESOLVED, DecisionReason::tryFrom('resource_unresolved'));
        self::assertSame(DecisionReason::TENANT_SCOPE, DecisionReason::tryFrom('tenant_scope'));
    }

    /**
     * tryFrom() returns null for an unknown value, and for each code the
     * reasons used to carry, which no longer exist.
     *
     * @return void
     */
    public function testTryFromReturnsNullForUnknownValue(): void
    {
        self::assertNull(DecisionReason::tryFrom('unknown'));
        self::assertNull(DecisionReason::tryFrom('explicit_allow'));
        self::assertNull(DecisionReason::tryFrom('implicit_deny'));
        self::assertNull(DecisionReason::tryFrom('rbac_allow'));
    }
}
