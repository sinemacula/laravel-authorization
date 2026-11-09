<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Reviews\Enums\ReviewKind;

/**
 * Unit tests for `ReviewKind`, the question an access review asks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReviewKind::class)]
final class ReviewKindTest extends TestCase
{
    /**
     * The cases are backed by the stable strings a review row's versioned shape
     * carries, in the order they are declared.
     *
     * @return void
     */
    public function testCasesAreBackedByStableStrings(): void
    {
        $values = \array_map(static fn (ReviewKind $case): string => $case->value, ReviewKind::cases());

        self::assertSame(['holders', 'holdings', 'expiring', 'granted_by'], $values);
    }
}
