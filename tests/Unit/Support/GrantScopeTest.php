<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for `GrantScope`, where a grant holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantScope::class)]
final class GrantScopeTest extends TestCase
{
    /**
     * The platform scope names no tenant and no application.
     *
     * @return void
     */
    public function testThePlatformScopeNamesNoTenantOrApplication(): void
    {
        self::assertEquals(new GrantScope(null, null), GrantScope::platform());
        self::assertTrue(GrantScope::platform()->includeSubtree);
    }

    /**
     * A scope names the tenant and the application it was given.
     *
     * @return void
     */
    public function testNamesItsTenantAndApplication(): void
    {
        $tenant = new Reference('stub_tenant', 'tenant-a');
        $scope  = new GrantScope($tenant, 'admin');

        self::assertSame($tenant, $scope->tenant);
        self::assertSame('admin', $scope->application);
        self::assertTrue($scope->includeSubtree);
        self::assertFalse((new GrantScope($tenant, null, false))->includeSubtree);
    }
}
