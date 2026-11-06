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
     * The enum defines exactly the six statement outcomes, the two permission
     * outcomes, the outcome of a guardrail or boundary that refuses the check,
     * the outcome of a cap stage that caps nothing and that of a cap stage the
     * check is exempt from, in declaration order.
     *
     * @return void
     */
    public function testExactlyElevenCases(): void
    {
        self::assertSame(
            [
                TraceOutcome::NOT_APPLICABLE,
                TraceOutcome::PRINCIPAL_MISMATCH,
                TraceOutcome::MATCHED,
                TraceOutcome::CONDITION_FAILED,
                TraceOutcome::UNDECIDABLE,
                TraceOutcome::INVALID,
                TraceOutcome::HELD,
                TraceOutcome::NOT_HELD,
                TraceOutcome::REFUSED,
                TraceOutcome::UNCAPPED,
                TraceOutcome::EXEMPT,
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
        self::assertSame('principal_mismatch', TraceOutcome::PRINCIPAL_MISMATCH->value);
        self::assertSame('matched', TraceOutcome::MATCHED->value);
        self::assertSame('condition_failed', TraceOutcome::CONDITION_FAILED->value);
        self::assertSame('undecidable', TraceOutcome::UNDECIDABLE->value);
        self::assertSame('invalid', TraceOutcome::INVALID->value);
        self::assertSame('held', TraceOutcome::HELD->value);
        self::assertSame('not_held', TraceOutcome::NOT_HELD->value);
        self::assertSame('refused', TraceOutcome::REFUSED->value);
        self::assertSame('uncapped', TraceOutcome::UNCAPPED->value);
        self::assertSame('exempt', TraceOutcome::EXEMPT->value);
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
        self::assertSame(TraceOutcome::PRINCIPAL_MISMATCH, TraceOutcome::tryFrom('principal_mismatch'));
        self::assertSame(TraceOutcome::MATCHED, TraceOutcome::tryFrom('matched'));
        self::assertSame(TraceOutcome::CONDITION_FAILED, TraceOutcome::tryFrom('condition_failed'));
        self::assertSame(TraceOutcome::UNDECIDABLE, TraceOutcome::tryFrom('undecidable'));
        self::assertSame(TraceOutcome::INVALID, TraceOutcome::tryFrom('invalid'));
        self::assertSame(TraceOutcome::HELD, TraceOutcome::tryFrom('held'));
        self::assertSame(TraceOutcome::NOT_HELD, TraceOutcome::tryFrom('not_held'));
        self::assertSame(TraceOutcome::REFUSED, TraceOutcome::tryFrom('refused'));
        self::assertSame(TraceOutcome::UNCAPPED, TraceOutcome::tryFrom('uncapped'));
        self::assertSame(TraceOutcome::EXEMPT, TraceOutcome::tryFrom('exempt'));
        self::assertNull(TraceOutcome::tryFrom('skipped'));
        self::assertNull(TraceOutcome::tryFrom('unknown'));
    }
}
