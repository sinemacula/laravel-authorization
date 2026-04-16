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
     * The case count matches the four-step evaluation model.
     *
     * @return void
     */
    public function testExactlyFourCases(): void
    {
        self::assertCount(4, DecisionReason::cases());
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
