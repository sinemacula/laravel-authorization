<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceDecision;

/**
 * Unit tests for the trace-decision enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(TraceDecision::class)]
final class TraceDecisionTest extends TestCase
{
    /**
     * Exactly two cases exist — matched and skipped.
     *
     * @return void
     */
    public function testExactlyTwoCases(): void
    {
        self::assertCount(2, TraceDecision::cases());
    }

    /**
     * Backing values are the expected strings.
     *
     * @return void
     */
    public function testBackingValues(): void
    {
        self::assertSame('matched', TraceDecision::MATCHED->value);
        self::assertSame('skipped', TraceDecision::SKIPPED->value);
    }

    /**
     * tryFrom() resolves known values and rejects unknowns.
     *
     * @return void
     */
    public function testTryFromResolvesCorrectly(): void
    {
        self::assertSame(TraceDecision::MATCHED, TraceDecision::tryFrom('matched'));
        self::assertSame(TraceDecision::SKIPPED, TraceDecision::tryFrom('skipped'));
        self::assertNull(TraceDecision::tryFrom('unknown'));
    }
}
