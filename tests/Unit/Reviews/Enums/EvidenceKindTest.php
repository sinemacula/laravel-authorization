<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Reviews\Enums\EvidenceKind;

/**
 * Unit tests for `EvidenceKind`, what gives the action an action-filtered
 * review of holdings asks about.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EvidenceKind::class)]
final class EvidenceKindTest extends TestCase
{
    /**
     * The cases are backed by the stable strings a review row's versioned shape
     * carries, in the order they are declared.
     *
     * @return void
     */
    public function testCasesAreBackedByStableStrings(): void
    {
        $values = \array_map(static fn (EvidenceKind $case): string => $case->value, EvidenceKind::cases());

        self::assertSame(['permission', 'policy_statement'], $values);
    }
}
