<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Reviews\Enums\GrantState;

/**
 * Unit tests for `GrantState`, whether a stored row still counts at a review's
 * instant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantState::class)]
final class GrantStateTest extends TestCase
{
    /**
     * The cases are backed by the stable strings a review row's versioned shape
     * carries, in the order they are declared.
     *
     * @return void
     */
    public function testCasesAreBackedByStableStrings(): void
    {
        $values = \array_map(static fn (GrantState $case): string => $case->value, GrantState::cases());

        self::assertSame(['live', 'expired', 'malformed'], $values);
    }
}
