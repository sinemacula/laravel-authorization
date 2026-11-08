<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Enums\GrantPresence;

/**
 * Unit tests for `GrantPresence`, whether a principal holds a grant that
 * applies in a tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantPresence::class)]
final class GrantPresenceTest extends TestCase
{
    /**
     * The answers are backed by stable strings.
     *
     * @return void
     */
    public function testAnswersAreBackedByStableStrings(): void
    {
        $values = \array_map(static fn (GrantPresence $presence): string => $presence->value, GrantPresence::cases());

        self::assertSame(['present', 'absent', 'unknown'], $values);
    }
}
