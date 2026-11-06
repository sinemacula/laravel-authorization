<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;

/**
 * Unit tests for `GrantOutcome`, what a grant through the services changed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantOutcome::class)]
final class GrantOutcomeTest extends TestCase
{
    /**
     * Every outcome but unchanged is a change.
     *
     * @return void
     */
    public function testEveryOutcomeButUnchangedIsAChange(): void
    {
        self::assertTrue(GrantOutcome::GRANTED->isChange());
        self::assertTrue(GrantOutcome::REARMED->isChange());
        self::assertTrue(GrantOutcome::EXPIRY_CHANGED->isChange());
        self::assertTrue(GrantOutcome::REACH_CHANGED->isChange());
        self::assertTrue(GrantOutcome::REPLACED->isChange());
        self::assertFalse(GrantOutcome::UNCHANGED->isChange());
    }

    /**
     * The outcomes are backed by stable strings.
     *
     * @return void
     */
    public function testOutcomesAreBackedByStableStrings(): void
    {
        $values = \array_map(static fn (GrantOutcome $outcome): string => $outcome->value, GrantOutcome::cases());

        self::assertSame(['granted', 'rearmed', 'expiry_changed', 'reach_changed', 'replaced', 'unchanged'], $values);
    }
}
