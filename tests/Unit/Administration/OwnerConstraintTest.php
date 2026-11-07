<?php

declare(strict_types = 1);

namespace Tests\Unit\Administration;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Administration\OwnerConstraint;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for `OwnerConstraint`: only the owner edits (D20).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OwnerConstraint::class)]
final class OwnerConstraintTest extends TestCase
{
    /**
     * A record is edited from its own tenant alone, compared by type and key,
     * and the platform's from the platform alone.
     *
     * @return void
     */
    public function testOnlyTheOwnersContextEdits(): void
    {
        $tenant = new Reference('tenant', 'a');

        self::assertTrue(OwnerConstraint::isOwner(null, null));
        self::assertTrue(OwnerConstraint::isOwner($tenant, new Reference('tenant', 'a')));
        self::assertFalse(OwnerConstraint::isOwner($tenant, null));
        self::assertFalse(OwnerConstraint::isOwner(null, $tenant));
        self::assertFalse(OwnerConstraint::isOwner($tenant, new Reference('tenant', 'b')));
        self::assertFalse(OwnerConstraint::isOwner($tenant, new Reference('team', 'a')));
        self::assertFalse(OwnerConstraint::isOwner($tenant, new Reference('tenant', 'A')));
    }
}
