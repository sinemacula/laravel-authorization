<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;

/**
 * Unit tests for the match-outcome enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MatchOutcome::class)]
final class MatchOutcomeTest extends TestCase
{
    /**
     * The enum defines exactly the four outcomes, in declaration order.
     *
     * @return void
     */
    public function testExactlyFourCases(): void
    {
        self::assertSame(
            [MatchOutcome::MATCHES, MatchOutcome::DOES_NOT_MATCH, MatchOutcome::UNDECIDABLE, MatchOutcome::INVALID],
            MatchOutcome::cases(),
        );
    }

    /**
     * Every case carries its documented backing value.
     *
     * @return void
     */
    public function testBackingValues(): void
    {
        self::assertSame('matches', MatchOutcome::MATCHES->value);
        self::assertSame('does_not_match', MatchOutcome::DOES_NOT_MATCH->value);
        self::assertSame('undecidable', MatchOutcome::UNDECIDABLE->value);
        self::assertSame('invalid', MatchOutcome::INVALID->value);
    }

    /**
     * tryFrom() resolves every known backing value and returns null for an
     * unknown one.
     *
     * @return void
     */
    public function testTryFromResolvesKnownValues(): void
    {
        self::assertSame(MatchOutcome::MATCHES, MatchOutcome::tryFrom('matches'));
        self::assertSame(MatchOutcome::DOES_NOT_MATCH, MatchOutcome::tryFrom('does_not_match'));
        self::assertSame(MatchOutcome::UNDECIDABLE, MatchOutcome::tryFrom('undecidable'));
        self::assertSame(MatchOutcome::INVALID, MatchOutcome::tryFrom('invalid'));
        self::assertNull(MatchOutcome::tryFrom('unknown'));
    }

    /**
     * precedence() returns the exact rank of every outcome.
     *
     * @return void
     */
    public function testPrecedenceValues(): void
    {
        self::assertSame(0, MatchOutcome::MATCHES->precedence());
        self::assertSame(1, MatchOutcome::UNDECIDABLE->precedence());
        self::assertSame(2, MatchOutcome::DOES_NOT_MATCH->precedence());
        self::assertSame(3, MatchOutcome::INVALID->precedence());
    }

    /**
     * precedence() orders the outcomes invalid, does not match, undecidable,
     * matches, from strongest to weakest.
     *
     * @return void
     */
    public function testPrecedenceOrder(): void
    {
        self::assertGreaterThan(MatchOutcome::DOES_NOT_MATCH->precedence(), MatchOutcome::INVALID->precedence());
        self::assertGreaterThan(MatchOutcome::UNDECIDABLE->precedence(), MatchOutcome::DOES_NOT_MATCH->precedence());
        self::assertGreaterThan(MatchOutcome::MATCHES->precedence(), MatchOutcome::UNDECIDABLE->precedence());
    }
}
