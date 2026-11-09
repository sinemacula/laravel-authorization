<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\ConditionOutcome;

/**
 * Unit tests for the condition-outcome enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConditionOutcome::class)]
final class ConditionOutcomeTest extends TestCase
{
    /**
     * The enum defines exactly its eight outcomes, each with its documented
     * backing value, in declaration order.
     *
     * @return void
     */
    public function testCasesAndBackingValues(): void
    {
        self::assertSame(
            ['held', 'failed', 'missing', 'null', 'wrong_type', 'unresolved', 'undecidable', 'invalid'],
            \array_map(static fn (ConditionOutcome $outcome): string => $outcome->value, ConditionOutcome::cases()),
        );
    }

    /**
     * Only a test that held holds.
     *
     * @return void
     */
    public function testOnlyHeldHolds(): void
    {
        foreach (ConditionOutcome::cases() as $outcome) {
            self::assertSame($outcome === ConditionOutcome::HELD, $outcome->holds(), $outcome->value);
        }
    }
}
