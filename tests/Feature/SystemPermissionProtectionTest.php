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
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use Tests\TestCase;

/**
 * Feature coverage for the system-permission protection flag.
 *
 * `is_system = true` blocks the next delete or edit on the instance unless
 * `forceSystem()` is called first; the bypass is per-instance, in-memory, and
 * single-use — it does not persist across `$permission->fresh()` hydrations and
 * re-arms on the next protected mutation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Permission::class)]
#[CoversClass(PermissionObserver::class)]
#[CoversClass(SystemPermissionProtectedException::class)]
#[CoversClass(TenantScope::class)]
#[CoversClass(ResolutionCacheContext::class)]
#[CoversClass(InvalidTenantException::class)]
#[CoversClass(InvalidTenantColumnsException::class)]
#[CoversClass(GuardScopedLookup::class)]
final class SystemPermissionProtectionTest extends TestCase
{
    /**
     * Deleting a system permission without the escape hatch is refused.
     *
     * @return void
     */
    public function testDeletingSystemPermissionIsRefused(): void
    {
        $permission = Permission::create([
            'id'        => (string) Str::uuid(),
            'name'      => '*:*',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        try {
            $permission->delete();
            self::fail('Expected SystemPermissionProtectedException was not thrown.');
        } catch (SystemPermissionProtectedException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame('*:*', $exception->getPermissionName());
            self::assertSame('delete', $exception->getOperation());
        }

        self::assertNotNull(Permission::query()->find($permission->getKey())); // @phpstan-ignore deadCode.unreachable
    }

    /**
     * Renaming a system permission without the escape hatch is refused.
     *
     * @return void
     */
    public function testRenamingSystemPermissionIsRefused(): void
    {
        $name = 'system:audit';

        $permission = Permission::create([
            'id'        => (string) Str::uuid(),
            'name'      => $name,
            'guard'     => 'web',
            'is_system' => true,
        ]);

        try {
            $permission->name = 'system:rebranded-audit';
            $permission->save();
            self::fail('Expected SystemPermissionProtectedException was not thrown.');
        } catch (SystemPermissionProtectedException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame($name, $exception->getPermissionName());
            self::assertSame('rename', $exception->getOperation());
        }

        self::assertSame($name, $permission->fresh()?->name); // @phpstan-ignore deadCode.unreachable
    }

    /**
     * A system permission loaded without its name is refused with the
     * protection exception, which names the permission by its key.
     *
     * @return void
     */
    public function testSystemPermissionLoadedWithoutNameIsNamedByKey(): void
    {
        $permission = Permission::create([
            'id'        => (string) Str::uuid(),
            'name'      => '*:*',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        $partial = Permission::query()->select(['id'])->findOrFail($permission->id);

        try {
            $partial->delete();
            self::fail('Expected SystemPermissionProtectedException was not thrown.');
        } catch (SystemPermissionProtectedException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame($permission->id, $exception->getPermissionName());
            self::assertSame('delete', $exception->getOperation());
        }

        self::assertNotNull(Permission::query()->find($permission->getKey())); // @phpstan-ignore deadCode.unreachable
    }

    /**
     * `forceSystem()` unlocks the next delete.
     *
     * @return void
     */
    public function testForceSystemAllowsDelete(): void
    {
        $permission = Permission::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'retired:permission',
            'guard'     => 'web',
            'is_system' => true,
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
            'id'        => (string) Str::uuid(),
            'name'      => 'legacy:name',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        $permission->forceSystem();
        $permission->name = 'new:canonical-name';
        $permission->save();

        self::assertSame('new:canonical-name', $permission->fresh()?->name);
    }

    /**
     * Every field of a system permission is protected, so a description update
     * without the escape hatch is refused as a `modify`.
     *
     * @return void
     */
    public function testDescriptionUpdateOnSystemPermissionIsRefused(): void
    {
        $permission = Permission::create([
            'id'        => (string) Str::uuid(),
            'name'      => '*:*',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        try {
            $permission->description = 'Super-admin permission — platform wildcard.';
            $permission->save();
            self::fail('Expected SystemPermissionProtectedException was not thrown.');
        } catch (SystemPermissionProtectedException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame('*:*', $exception->getPermissionName());
            self::assertSame('modify', $exception->getOperation());
        }

        self::assertNull($permission->fresh()?->description); // @phpstan-ignore deadCode.unreachable
    }

    /**
     * Clearing the system flag in the same mass-assigned update as a rename is
     * refused as an `unprotect`: the guard reads the persisted flag, not the
     * dirty one.
     *
     * @return void
     */
    public function testClearingSystemFlagThroughMassAssignmentIsRefused(): void
    {
        $permission = Permission::create([
            'id'        => (string) Str::uuid(),
            'name'      => '*:*',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        try {
            $permission->update(['is_system' => false, 'name' => 'renamed']);
            self::fail('Expected SystemPermissionProtectedException was not thrown.');
        } catch (SystemPermissionProtectedException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame('*:*', $exception->getPermissionName());
            self::assertSame('unprotect', $exception->getOperation());
        }

        $fresh = $permission->fresh(); // @phpstan-ignore deadCode.unreachable

        self::assertSame('*:*', $fresh?->name);
        self::assertTrue($fresh?->is_system);
    }

    /**
     * Clearing the system flag in memory and then deleting is refused, because
     * the persisted flag still marks the row as system.
     *
     * @return void
     */
    public function testClearingSystemFlagThenDeletingIsRefused(): void
    {
        $permission = Permission::create([
            'id'        => (string) Str::uuid(),
            'name'      => '*:*',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        $permission->is_system = false;

        try {
            $permission->delete();
            self::fail('Expected SystemPermissionProtectedException was not thrown.');
        } catch (SystemPermissionProtectedException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame('delete', $exception->getOperation());
        }

        self::assertNotNull(Permission::query()->find($permission->getKey())); // @phpstan-ignore deadCode.unreachable
    }

    /**
     * `forceSystem()` unlocks clearing the flag, after which the row is no
     * longer protected and deletes freely.
     *
     * @return void
     */
    public function testForceSystemAllowsClearingSystemFlag(): void
    {
        $permission = Permission::create([
            'id'        => (string) Str::uuid(),
            'name'      => '*:*',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        $permission->forceSystem()->update(['is_system' => false]);

        self::assertFalse($permission->fresh()?->is_system);

        $permission->delete();

        self::assertNull(Permission::query()->find($permission->getKey()));
    }

    /**
     * The bypass is single-use — after one protected mutation the next one
     * re-arms.
     *
     * @return void
     */
    public function testForceSystemIsSingleUse(): void
    {
        $permission = Permission::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'volatile:permission',
            'guard'     => 'web',
            'is_system' => true,
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
     * `forceSystem()` is cleared by an intervening unprotected save (a
     * `touch()`), so a subsequent rename without re-arming the bypass is
     * refused.
     *
     * @return void
     */
    public function testBypassDoesNotHopAcrossUnrelatedSave(): void
    {
        $permission = Permission::create([
            'id'        => (string) Str::uuid(),
            'name'      => '*:*',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        $permission->forceSystem();
        $permission->touch();

        $this->expectException(SystemPermissionProtectedException::class);

        $permission->name = 'renamed:without-bypass';
        $permission->save();
    }

    /**
     * Non-system permissions behave as before — no protection, no bypass
     * required.
     *
     * @return void
     */
    public function testNonSystemPermissionsDeleteFreely(): void
    {
        $permission = Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'ordinary:permission',
            'guard' => 'web',
        ]);

        self::assertFalse((bool) $permission->is_system); // @phpstan-ignore cast.useless

        $permission->delete();

        self::assertNull(Permission::query()->find($permission->getKey()));
    }
}
