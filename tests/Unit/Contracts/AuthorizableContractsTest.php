<?php

declare(strict_types = 1);

namespace Tests\Unit\Contracts;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Contracts\SupportsPermissions;
use SineMacula\Laravel\Authorization\Contracts\SupportsPolicies;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;

/**
 * Unit tests for the interface-segregated authorizable contract surface.
 *
 * Consumers who only use a subset of the surface can typehint on the narrow
 * siblings (`SupportsRoles`, `SupportsPermissions`, `SupportsPolicies`). The
 * composite `AuthorizableIdentity` extends all three, so existing implementers
 * stay satisfied and `instanceof` checks keep working against the fat and
 * narrow contracts alike.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversNothing]
final class AuthorizableContractsTest extends TestCase
{
    /**
     * Every narrow contract is extended by the composite — pins the
     * interface-segregation invariant.
     *
     * @return void
     */
    public function testCompositeExtendsEveryNarrowContract(): void
    {
        $parents = class_implements(AuthorizableIdentity::class);

        self::assertNotFalse($parents);
        self::assertArrayHasKey(SupportsRoles::class, $parents);
        self::assertArrayHasKey(SupportsPermissions::class, $parents);
        self::assertArrayHasKey(SupportsPolicies::class, $parents);
    }

    /**
     * Each narrow contract declares only the methods on its slice — role
     * helpers on `SupportsRoles`, permission helpers on `SupportsPermissions`,
     * policy helpers on `SupportsPolicies`.
     *
     * @return void
     */
    public function testNarrowContractsExposeOnlyTheirSliceOfTheSurface(): void
    {
        $roles       = array_map(static fn ($m): string => $m->getName(), (new \ReflectionClass(SupportsRoles::class))->getMethods());
        $permissions = array_map(static fn ($m): string => $m->getName(), (new \ReflectionClass(SupportsPermissions::class))->getMethods());
        $policies    = array_map(static fn ($m): string => $m->getName(), (new \ReflectionClass(SupportsPolicies::class))->getMethods());

        self::assertSame(
            ['assignRole', 'revokeRole', 'syncRoles', 'hasRole', 'getRoles'],
            $roles,
        );
        self::assertSame(
            ['givePermission', 'revokePermission', 'syncPermissions', 'hasPermission', 'getPermissions'],
            $permissions,
        );
        self::assertSame(
            ['attachPolicy', 'detachPolicy', 'syncPolicies', 'getPolicies'],
            $policies,
        );
    }
}
