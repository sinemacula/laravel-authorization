<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Enums\GrantScopeStatus;

/**
 * Unit tests for `GrantScopeStatus`, where an identity's grants lie against a
 * tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantScopeStatus::class)]
final class GrantScopeStatusTest extends TestCase
{
    /**
     * The statuses are backed by the stable strings `laravel-iam` composes.
     *
     * @return void
     */
    public function testStatusesAreBackedByStableStrings(): void
    {
        $values = \array_map(static fn (GrantScopeStatus $status): string => $status->value, GrantScopeStatus::cases());

        self::assertSame(['within', 'outside', 'unknown'], $values);
    }
}
