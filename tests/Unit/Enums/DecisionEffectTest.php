<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;

/**
 * Unit tests for the decision-effect enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DecisionEffect::class)]
final class DecisionEffectTest extends TestCase
{
    /**
     * The enum defines exactly the two effects, allow then deny.
     *
     * @return void
     */
    public function testExactlyTwoCases(): void
    {
        self::assertSame([DecisionEffect::ALLOW, DecisionEffect::DENY], DecisionEffect::cases());
    }

    /**
     * Every case carries its documented backing value.
     *
     * @return void
     */
    public function testBackingValues(): void
    {
        self::assertSame('allow', DecisionEffect::ALLOW->value);
        self::assertSame('deny', DecisionEffect::DENY->value);
    }

    /**
     * tryFrom() resolves every known backing value and returns null for an
     * unknown one.
     *
     * @return void
     */
    public function testTryFromResolvesKnownValues(): void
    {
        self::assertSame(DecisionEffect::ALLOW, DecisionEffect::tryFrom('allow'));
        self::assertSame(DecisionEffect::DENY, DecisionEffect::tryFrom('deny'));
        self::assertNull(DecisionEffect::tryFrom('unknown'));
    }
}
