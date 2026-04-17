<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;

/**
 * Unit tests for the policy effect enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PolicyEffect::class)]
final class PolicyEffectTest extends TestCase
{
    /**
     * Verify the enum exposes the allow and deny cases.
     *
     * @return void
     */
    public function testExposesAllowAndDenyCases(): void
    {
        self::assertSame('allow', PolicyEffect::Allow->value);
        self::assertSame('deny', PolicyEffect::Deny->value);
    }

    /**
     * Verify tryFrom returns null on unknown input.
     *
     * @return void
     */
    public function testTryFromReturnsNullOnUnknownValue(): void
    {
        self::assertNull(PolicyEffect::tryFrom('audit'));
    }
}
