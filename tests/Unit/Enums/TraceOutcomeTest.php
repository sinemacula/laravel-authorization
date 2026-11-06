<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;

/**
 * Unit tests for the trace-outcome enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(TraceOutcome::class)]
final class TraceOutcomeTest extends TestCase
{
    /**
     * The enum defines exactly the five statement outcomes and the two
     * permission outcomes, in declaration order.
     *
     * @return void
     */
    public function testExactlySevenCases(): void
    {
        self::assertSame(
            [
                TraceOutcome::NOT_APPLICABLE,
                TraceOutcome::MATCHED,
                TraceOutcome::CONDITION_FAILED,
                TraceOutcome::UNDECIDABLE,
                TraceOutcome::INVALID,
                TraceOutcome::HELD,
                TraceOutcome::NOT_HELD,
            ],
            TraceOutcome::cases(),
        );
    }

    /**
     * Every case carries its documented backing value.
     *
     * @return void
     */
    public function testBackingValues(): void
    {
        self::assertSame('not_applicable', TraceOutcome::NOT_APPLICABLE->value);
        self::assertSame('matched', TraceOutcome::MATCHED->value);
        self::assertSame('condition_failed', TraceOutcome::CONDITION_FAILED->value);
        self::assertSame('undecidable', TraceOutcome::UNDECIDABLE->value);
        self::assertSame('invalid', TraceOutcome::INVALID->value);
        self::assertSame('held', TraceOutcome::HELD->value);
        self::assertSame('not_held', TraceOutcome::NOT_HELD->value);
    }

    /**
     * tryFrom() resolves every known backing value and returns null for an
     * unknown one, and for the skipped decision the trace used to carry.
     *
     * @return void
     */
    public function testTryFromResolvesKnownValues(): void
    {
        self::assertSame(TraceOutcome::NOT_APPLICABLE, TraceOutcome::tryFrom('not_applicable'));
        self::assertSame(TraceOutcome::MATCHED, TraceOutcome::tryFrom('matched'));
        self::assertSame(TraceOutcome::CONDITION_FAILED, TraceOutcome::tryFrom('condition_failed'));
        self::assertSame(TraceOutcome::UNDECIDABLE, TraceOutcome::tryFrom('undecidable'));
        self::assertSame(TraceOutcome::INVALID, TraceOutcome::tryFrom('invalid'));
        self::assertSame(TraceOutcome::HELD, TraceOutcome::tryFrom('held'));
        self::assertSame(TraceOutcome::NOT_HELD, TraceOutcome::tryFrom('not_held'));
        self::assertNull(TraceOutcome::tryFrom('skipped'));
        self::assertNull(TraceOutcome::tryFrom('unknown'));
    }
}
