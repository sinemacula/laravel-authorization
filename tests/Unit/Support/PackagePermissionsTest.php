<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;

/**
 * Unit tests for the permissions the package declares for its own services.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PackagePermissions::class)]
final class PackagePermissionsTest extends TestCase
{
    /**
     * The package declares the right to manage guardrails, guard-agnostic,
     * described and filed under its own category, as a permission provider.
     *
     * @return void
     */
    public function testDeclaresTheRightToManageGuardrails(): void
    {
        $permissions = new PackagePermissions;

        self::assertInstanceOf(PermissionProvider::class, $permissions);
        self::assertSame('authorization:guardrails:manage', PackagePermissions::GUARDRAILS_MANAGE);
        self::assertEquals(
            [new PermissionDefinition('authorization:guardrails:manage', 'Set and remove guardrails from above the scope they cap.', 'authorization')],
            $permissions->permissions(),
        );
        self::assertNull($permissions->permissions()[0]->guard);
    }
}
