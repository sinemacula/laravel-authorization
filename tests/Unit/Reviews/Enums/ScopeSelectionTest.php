<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Reviews\Enums\ScopeSelection;

/**
 * Unit tests for `ScopeSelection`, how an access review selects the grants it
 * reads.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ScopeSelection::class)]
final class ScopeSelectionTest extends TestCase
{
    /**
     * The cases are backed by the stable strings a review row's versioned shape
     * carries, in the order they are declared.
     *
     * @return void
     */
    public function testCasesAreBackedByStableStrings(): void
    {
        $values = \array_map(static fn (ScopeSelection $case): string => $case->value, ScopeSelection::cases());

        self::assertSame(['applies_in', 'rooted_within', 'everywhere'], $values);
    }
}
