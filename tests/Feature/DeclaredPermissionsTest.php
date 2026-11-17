<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\UndeclaredPermissionException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Support\DeclaredPermissions;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use Tests\Concerns\DeclaresPermissions;
use Tests\Feature\Stubs\EmptyActionCatalogue;
use Tests\Feature\Stubs\PermissiveActionCatalogue;
use Tests\TestCase;

/**
 * Feature tests for `DeclaredPermissions`, the rule every created, renamed or
 * granted permission and every policy action pattern is held to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeclaredPermissions::class)]
final class DeclaredPermissionsTest extends TestCase
{
    use DeclaresPermissions;

    /**
     * A pattern is covered by one of the package's own permissions whatever the
     * catalogue holds, and by the catalogue otherwise.
     *
     * @return void
     */
    public function testCoversThePackagesOwnOrTheCataloguesActions(): void
    {
        self::assertTrue(DeclaredPermissions::covers(PackagePermissions::ROLE_GRANT, new EmptyActionCatalogue));
        self::assertTrue(DeclaredPermissions::covers('authorization:*', new EmptyActionCatalogue));
        self::assertTrue(DeclaredPermissions::covers('posts:read', new PermissiveActionCatalogue));
        self::assertFalse(DeclaredPermissions::covers('posts:read', new EmptyActionCatalogue));
    }

    /**
     * The bound catalogue decides a name: a declared one, a wildcard covering
     * one and the package's own pass, and anything else is refused.
     *
     * @return void
     */
    public function testAssertRefusesANameTheBoundCatalogueDoesNotDeclare(): void
    {
        $this->declarePermissions('posts:read');

        foreach (['posts:read', 'posts:*', '*', PackagePermissions::PERMISSION_CREATE] as $name) {
            DeclaredPermissions::assert($name);
        }

        foreach (['posts:delete', 'comments:*'] as $name) {
            try {
                DeclaredPermissions::assert($name);
                self::fail("'{$name}' was not refused.");
            } catch (UndeclaredPermissionException $exception) {
                self::assertSame($name, $exception->getPermission());
            }
        }
    }

    /**
     * A stored permission is judged on the name its row holds, not on one
     * changed in hand.
     *
     * @return void
     */
    public function testAssertStoredJudgesTheStoredName(): void
    {
        $this->declarePermissions('posts:read');

        $declared = Permission::query()->create(['name' => 'posts:read']);
        $stale    = Permission::query()->create(['name' => 'posts:legacy']);

        $declared->name = 'posts:invented';
        $stale->name    = 'posts:read';

        DeclaredPermissions::assertStored($declared);

        $this->expectExceptionObject(new UndeclaredPermissionException('posts:legacy'));

        DeclaredPermissions::assertStored($stale);
    }
}
