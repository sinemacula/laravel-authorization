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

    /**
     * Only the name of a permission the package declares is one of its own:
     * never a pattern covering it, nor a name that differs in case.
     *
     * @return void
     */
    public function testTellsItsOwnNamesApart(): void
    {
        self::assertTrue(PackagePermissions::isDeclared('authorization:guardrails:manage'));

        foreach (['authorization:*', 'authorization:guardrails', 'AUTHORIZATION:GUARDRAILS:MANAGE', 'posts:create', ''] as $name) {
            self::assertFalse(PackagePermissions::isDeclared($name), $name);
        }
    }

    /**
     * A pattern covers the package's permissions when it is one of their names
     * or matches one as statements match actions, a backslash literally.
     *
     * @return void
     */
    public function testCoversItsOwnPermissionsByNameOrPattern(): void
    {
        foreach (['authorization:guardrails:manage', 'authorization:*', 'authorization:guardrails:*', '*', 'authorization:guardrails:manag?'] as $pattern) {
            self::assertTrue(PackagePermissions::covers($pattern), $pattern);
        }

        foreach (['authorization:roles:*', 'authorization:guardrails', 'AUTHORIZATION:*', 'authorization\:*', 'posts:*', ''] as $pattern) {
            self::assertFalse(PackagePermissions::covers($pattern), $pattern);
        }
    }
}
