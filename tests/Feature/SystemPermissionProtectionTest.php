<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Exceptions\SystemPermissionProtectedException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Observers\PermissionObserver;
use SineMacula\Laravel\Authorization\Resolvers\NullTenantResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use Tests\TestCase;

/**
 * Feature coverage for the system-permission protection flag.
 *
 * `is_system = true` blocks the next delete or rename on the
 * instance unless `forceSystem()` is called first; the bypass is
 * per-instance, in-memory, and single-use — it does not persist
 * across `$permission->fresh()` hydrations and re-arms on the next
 * protected mutation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Permission::class)]
#[CoversClass(PermissionObserver::class)]
#[CoversClass(SystemPermissionProtectedException::class)]
#[CoversClass(TenantScope::class)]
#[CoversClass(NullTenantResolver::class)]
#[CoversClass(ResolutionCacheContext::class)]
#[CoversClass(InvalidTenantException::class)]
#[CoversClass(InvalidTenantColumnsException::class)]
#[CoversClass(GuardScopedLookup::class)]
final class SystemPermissionProtectionTest extends TestCase
{
    /**
     * Deleting a system permission without the escape hatch is
     * refused.
     *
     * @return void
     */
    public function testDeletingSystemPermissionIsRefused(): void
    {
        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => '*:*',
            'guard_name' => 'web',
            'is_system'  => true,
        ]);

        try {
            $permission->delete();
            self::fail('Expected SystemPermissionProtectedException was not thrown.');
        } catch (SystemPermissionProtectedException $exception) {
            self::assertSame('*:*', $exception->getPermissionName());
            self::assertSame('delete', $exception->getOperation());
        }

        self::assertNotNull(Permission::query()->find($permission->getKey()));
    }

    /**
     * Renaming a system permission without the escape hatch is
     * refused.
     *
     * @return void
     */
    public function testRenamingSystemPermissionIsRefused(): void
    {
        $name = 'system:audit';

        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => $name,
            'guard_name' => 'web',
            'is_system'  => true,
        ]);

        try {
            $permission->name = 'system:rebranded-audit';
            $permission->save();
            self::fail('Expected SystemPermissionProtectedException was not thrown.');
        } catch (SystemPermissionProtectedException $exception) {
            self::assertSame($name, $exception->getPermissionName());
            self::assertSame('rename', $exception->getOperation());
        }

        self::assertSame($name, $permission->fresh()?->name);
    }

    /**
     * `forceSystem()` unlocks the next delete.
     *
     * @return void
     */
    public function testForceSystemAllowsDelete(): void
    {
        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'retired:permission',
            'guard_name' => 'web',
            'is_system'  => true,
        ]);

        $permission->forceSystem()->delete();

        self::assertNull(Permission::query()->find($permission->getKey()));
    }

    /**
     * `forceSystem()` unlocks the next rename.
     *
     * @return void
     */
    public function testForceSystemAllowsRename(): void
    {
        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'legacy:name',
            'guard_name' => 'web',
            'is_system'  => true,
        ]);

        $permission->forceSystem();
        $permission->name = 'new:canonical-name';
        $permission->save();

        self::assertSame('new:canonical-name', $permission->fresh()?->name);
    }

    /**
     * Non-rename updates — description, guard_name swap — pass
     * without needing the escape hatch.
     *
     * @return void
     */
    public function testDescriptionUpdateOnSystemPermissionPasses(): void
    {
        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => '*:*',
            'guard_name' => 'web',
            'is_system'  => true,
        ]);

        $permission->description = 'Super-admin permission — platform wildcard.';
        $permission->save();

        self::assertSame(
            'Super-admin permission — platform wildcard.',
            $permission->fresh()?->description,
        );
    }

    /**
     * The bypass is single-use — after one protected mutation
     * the next one re-arms.
     *
     * @return void
     */
    public function testForceSystemIsSingleUse(): void
    {
        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'volatile:permission',
            'guard_name' => 'web',
            'is_system'  => true,
        ]);

        $permission->forceSystem();
        $permission->name = 'renamed:once';
        $permission->save();

        self::assertSame('renamed:once', $permission->fresh()?->name);

        $this->expectException(SystemPermissionProtectedException::class);

        $permission->name = 'second:rename';
        $permission->save();
    }

    /**
     * `forceSystem()` is consumed by an intervening non-protected
     * save (e.g. a description update), so a subsequent rename
     * without re-arming the bypass is refused.
     *
     * @return void
     */
    public function testBypassDoesNotHopAcrossUnrelatedSave(): void
    {
        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => '*:*',
            'guard_name' => 'web',
            'is_system'  => true,
        ]);

        $permission->forceSystem();
        $permission->description = 'Updated description.';
        $permission->save();

        $this->expectException(SystemPermissionProtectedException::class);

        $permission->name = 'renamed:without-bypass';
        $permission->save();
    }

    /**
     * Non-system permissions behave as before — no protection,
     * no bypass required.
     *
     * @return void
     */
    public function testNonSystemPermissionsDeleteFreely(): void
    {
        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'ordinary:permission',
            'guard_name' => 'web',
        ]);

        self::assertFalse((bool) $permission->is_system);

        $permission->delete();

        self::assertNull(Permission::query()->find($permission->getKey()));
    }
}
