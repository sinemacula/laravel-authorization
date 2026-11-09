<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;

/**
 * Unit tests for `SourceKind`, the kind of source a review row comes from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SourceKind::class)]
final class SourceKindTest extends TestCase
{
    /**
     * The cases are backed by the stable strings a review row's versioned shape
     * carries, in the order they are declared.
     *
     * @return void
     */
    public function testCasesAreBackedByStableStrings(): void
    {
        $values = \array_map(static fn (SourceKind $case): string => $case->value, SourceKind::cases());

        self::assertSame(
            ['role_grant', 'role_inherited', 'permission_grant', 'role_permission', 'policy_attachment', 'role_policy', 'role_permission_edge', 'role_policy_attachment'],
            $values,
        );
    }

    /**
     * Each kind's position is its place among the declared cases, the order a
     * review lists its rows in.
     *
     * @return void
     */
    public function testEachKindsPositionIsItsDeclaredPlace(): void
    {
        $positions = \array_map(static fn (SourceKind $kind): int => $kind->position(), SourceKind::cases());

        self::assertSame([0, 1, 2, 3, 4, 5, 6, 7], $positions);
        self::assertSame(0, SourceKind::ROLE_GRANT->position());
        self::assertSame(7, SourceKind::ROLE_POLICY_ATTACHMENT->position());
    }
}
