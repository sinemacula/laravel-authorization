<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Support\InheritedPermissions;

/**
 * Unit tests for the permissions a set of roles carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InheritedPermissions::class)]
final class InheritedPermissionsTest extends TestCase
{
    /**
     * The names and expiry are kept as given, and which role carries which
     * permission only when it was read.
     *
     * @return void
     */
    public function testTheValuesAreKept(): void
    {
        $plain  = new InheritedPermissions(['posts:read'], 60);
        $routed = new InheritedPermissions(['posts:read'], null, ['role-1' => [['id' => 'p', 'name' => 'posts:read']]]);

        self::assertSame([['posts:read'], 60, null], [$plain->names, $plain->expiresIn, $plain->byRole]);
        self::assertSame(['role-1' => [['id' => 'p', 'name' => 'posts:read']]], $routed->byRole);
    }
}
