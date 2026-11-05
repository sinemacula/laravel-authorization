<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
use SineMacula\Laravel\Authorization\Concerns\HasRoleHierarchy;
use SineMacula\Laravel\Authorization\Concerns\ManagesPermissions;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Exceptions\SystemRoleProtectedException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use SineMacula\Laravel\Authorization\Resolvers\NullTenantResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use Tests\TestCase;

/**
 * Feature coverage for the system-role protection flag.
 *
 * `is_system = true` blocks the next delete or edit on the instance unless
 * `forceSystem()` is called first; the bypass is per-instance, in-memory, and
 * single-use — it does not persist across `$role->fresh()` hydrations and
 * re-arms on the next protected mutation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Role::class)]
#[CoversClass(RoleObserver::class)]
#[CoversClass(SystemRoleProtectedException::class)]
#[CoversClass(TenantScope::class)]
#[CoversClass(NullTenantResolver::class)]
#[CoversClass(ResolutionCacheContext::class)]
#[CoversClass(InvalidTenantException::class)]
#[CoversClass(InvalidTenantColumnsException::class)]
#[CoversClass(GuardScopedLookup::class)]
#[CoversTrait(HasRoleHierarchy::class)]
#[CoversTrait(ManagesPermissions::class)]
final class SystemRoleProtectionTest extends TestCase
{
    /**
     * Deleting a system role without the escape hatch is refused.
     *
     * @return void
     */
    public function testDeletingSystemRoleIsRefused(): void
    {
        $role = Role::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'super-admin',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        try {
            $role->delete();
            self::fail('Expected SystemRoleProtectedException was not thrown.');
        } catch (SystemRoleProtectedException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame('super-admin', $exception->getRoleName());
            self::assertSame('delete', $exception->getOperation());
        }

        self::assertNotNull(Role::query()->find($role->getKey())); // @phpstan-ignore deadCode.unreachable
    }

    /**
     * Renaming a system role without the escape hatch is refused.
     *
     * @return void
     */
    public function testRenamingSystemRoleIsRefused(): void
    {
        $role = Role::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'auditor',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        try {
            $role->name = 'rebranded-auditor';
            $role->save();
            self::fail('Expected SystemRoleProtectedException was not thrown.');
        } catch (SystemRoleProtectedException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame('auditor', $exception->getRoleName());
            self::assertSame('rename', $exception->getOperation());
        }

        self::assertSame('auditor', $role->fresh()?->name); // @phpstan-ignore deadCode.unreachable
    }

    /**
     * `forceSystem()` unlocks the next delete.
     *
     * @return void
     */
    public function testForceSystemAllowsDelete(): void
    {
        $role = Role::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'retired-platform-role',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        $role->forceSystem()->delete();

        self::assertNull(Role::query()->find($role->getKey()));
    }

    /**
     * `forceSystem()` unlocks the next rename.
     *
     * @return void
     */
    public function testForceSystemAllowsRename(): void
    {
        $role = Role::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'legacy-name',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        $role->forceSystem();
        $role->name = 'new-canonical-name';
        $role->save();

        self::assertSame('new-canonical-name', $role->fresh()?->name);
    }

    /**
     * Every field of a system role is protected, so a description update
     * without the escape hatch is refused as a `modify`.
     *
     * @return void
     */
    public function testDescriptionUpdateOnSystemRoleIsRefused(): void
    {
        $role = Role::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'super-admin',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        try {
            $role->description = 'Super-admin — platform ownership.';
            $role->save();
            self::fail('Expected SystemRoleProtectedException was not thrown.');
        } catch (SystemRoleProtectedException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame('super-admin', $exception->getRoleName());
            self::assertSame('modify', $exception->getOperation());
        }

        self::assertNull($role->fresh()?->description); // @phpstan-ignore deadCode.unreachable
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
        $role = Role::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'super-admin',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        try {
            $role->update(['is_system' => false, 'name' => 'renamed']);
            self::fail('Expected SystemRoleProtectedException was not thrown.');
        } catch (SystemRoleProtectedException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame('super-admin', $exception->getRoleName());
            self::assertSame('unprotect', $exception->getOperation());
        }

        $fresh = $role->fresh(); // @phpstan-ignore deadCode.unreachable

        self::assertSame('super-admin', $fresh?->name);
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
        $role = Role::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'super-admin',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        $role->is_system = false;

        try {
            $role->delete();
            self::fail('Expected SystemRoleProtectedException was not thrown.');
        } catch (SystemRoleProtectedException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame('delete', $exception->getOperation());
        }

        self::assertNotNull(Role::query()->find($role->getKey())); // @phpstan-ignore deadCode.unreachable
    }

    /**
     * `forceSystem()` unlocks clearing the flag, after which the row is no
     * longer protected and deletes freely.
     *
     * @return void
     */
    public function testForceSystemAllowsClearingSystemFlag(): void
    {
        $role = Role::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'super-admin',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        $role->forceSystem()->update(['is_system' => false]);

        self::assertFalse($role->fresh()?->is_system);

        $role->delete();

        self::assertNull(Role::query()->find($role->getKey()));
    }

    /**
     * The bypass is single-use — after one protected mutation the next one
     * re-arms.
     *
     * @return void
     */
    public function testForceSystemIsSingleUse(): void
    {
        $role = Role::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'volatile',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        $role->forceSystem();
        $role->name = 'renamed-once';
        $role->save();

        self::assertSame('renamed-once', $role->fresh()?->name);

        $this->expectException(SystemRoleProtectedException::class);

        $role->name = 'second-rename';
        $role->save();
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
        $role = Role::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'super-admin',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        // Arm the bypass, then perform a save the guard does not inspect, so
        // `updating` never consumes the flag.
        $role->forceSystem();
        $role->touch();

        // The bypass must be gone: a rename without a fresh `forceSystem()`
        // call must be refused.
        $this->expectException(SystemRoleProtectedException::class);

        $role->name = 'renamed-without-bypass';
        $role->save();
    }

    /**
     * `forceSystem()` followed immediately by `delete()` still succeeds — the
     * `saved` reset must not interfere with the delete path, which has no
     * `saved` event.
     *
     * @return void
     */
    public function testForceSystemImmediatelyFollowedByDeleteStillWorks(): void
    {
        $role = Role::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'decommissioned',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        $role->forceSystem()->delete();

        self::assertNull(Role::query()->find($role->getKey()));
    }

    /**
     * Non-system roles behave as before — no protection, no bypass required.
     *
     * @return void
     */
    public function testNonSystemRolesDeleteFreely(): void
    {
        $role = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'ordinary',
            'guard' => 'web',
        ]);

        self::assertFalse((bool) $role->is_system); // @phpstan-ignore cast.useless

        $role->delete();

        self::assertNull(Role::query()->find($role->getKey()));
    }
}
