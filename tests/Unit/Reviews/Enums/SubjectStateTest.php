<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Reviews\Enums\SubjectState;

/**
 * Unit tests for `SubjectState`, what a review knows of a row's subject.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectState::class)]
final class SubjectStateTest extends TestCase
{
    /**
     * The cases are backed by the stable strings a review row's versioned shape
     * carries, in the order they are declared.
     *
     * @return void
     */
    public function testCasesAreBackedByStableStrings(): void
    {
        $values = \array_map(static fn (SubjectState $case): string => $case->value, SubjectState::cases());

        self::assertSame(['active', 'inactive', 'unknown'], $values);
    }
}
