<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\SystemRoleProtectedException;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\TestCase;

/**
 * Feature coverage for the system-role protection flag.
 *
 * `is_system = true` blocks the next delete or rename on the
 * instance unless `forceSystem()` is called first; the bypass is
 * per-instance, in-memory, and single-use — it does not persist
 * across `$role->fresh()` hydrations and re-arms on the next
 * protected mutation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Role::class)]
#[CoversClass(SystemRoleProtectedException::class)]
final class SystemRoleProtectionTest extends TestCase
{
    /**
     * Deleting a system role without the escape hatch is
     * refused.
     *
     * @return void
     */
    public function testDeletingSystemRoleIsRefused(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'super-admin',
            'guard_name' => 'web',
            'is_system'  => true,
        ]);

        try {
            $role->delete();
            self::fail('Expected SystemRoleProtectedException was not thrown.');
        } catch (SystemRoleProtectedException $exception) {
            self::assertSame('super-admin', $exception->getRoleName());
            self::assertSame('delete', $exception->getOperation());
        }

        self::assertNotNull(Role::query()->find($role->getKey()));
    }

    /**
     * Renaming a system role without the escape hatch is
     * refused.
     *
     * @return void
     */
    public function testRenamingSystemRoleIsRefused(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'auditor',
            'guard_name' => 'web',
            'is_system'  => true,
        ]);

        try {
            $role->name = 'rebranded-auditor';
            $role->save();
            self::fail('Expected SystemRoleProtectedException was not thrown.');
        } catch (SystemRoleProtectedException $exception) {
            self::assertSame('auditor', $exception->getRoleName());
            self::assertSame('rename', $exception->getOperation());
        }

        self::assertSame('auditor', $role->fresh()?->name);
    }

    /**
     * `forceSystem()` unlocks the next delete.
     *
     * @return void
     */
    public function testForceSystemAllowsDelete(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'retired-platform-role',
            'guard_name' => 'web',
            'is_system'  => true,
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
            'id'         => (string) Str::uuid(),
            'name'       => 'legacy-name',
            'guard_name' => 'web',
            'is_system'  => true,
        ]);

        $role->forceSystem();
        $role->name = 'new-canonical-name';
        $role->save();

        self::assertSame('new-canonical-name', $role->fresh()?->name);
    }

    /**
     * Non-rename updates — description, guard_name swap — pass
     * without needing the escape hatch.
     *
     * @return void
     */
    public function testDescriptionUpdateOnSystemRolePasses(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'super-admin',
            'guard_name' => 'web',
            'is_system'  => true,
        ]);

        $role->description = 'Super-admin — platform ownership.';
        $role->save();

        self::assertSame('Super-admin — platform ownership.', $role->fresh()?->description);
    }

    /**
     * The bypass is single-use — after one protected mutation
     * the next one re-arms.
     *
     * @return void
     */
    public function testForceSystemIsSingleUse(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'volatile',
            'guard_name' => 'web',
            'is_system'  => true,
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
     * Non-system roles behave as before — no protection, no
     * bypass required.
     *
     * @return void
     */
    public function testNonSystemRolesDeleteFreely(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'ordinary',
            'guard_name' => 'web',
        ]);

        self::assertFalse((bool) $role->is_system);

        $role->delete();

        self::assertNull(Role::query()->find($role->getKey()));
    }
}
