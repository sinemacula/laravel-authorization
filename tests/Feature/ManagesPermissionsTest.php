<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\ManagesPermissions;
use SineMacula\Laravel\Authorization\Events\Role\PermissionGranted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionRevoked;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\RoleService;
use Tests\Concerns\ComparesReferences;
use Tests\TestCase;

/**
 * Feature tests for the role-side permission writes of `ManagesPermissions`,
 * which go through the role service.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ManagesPermissions::class)]
final class ManagesPermissionsTest extends TestCase
{
    use ComparesReferences;

    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * The write methods go through the role service: granting what the role
     * carries dispatches nothing, and each returns the role.
     *
     * @return void
     */
    public function testWritesGoThroughTheRoleService(): void
    {
        Event::fake([PermissionGranted::class, PermissionRevoked::class]);

        $role       = Role::query()->create(['name' => 'editor', 'guard' => 'web']);
        $permission = Permission::query()->create(['name' => 'posts:edit', 'guard' => 'web']);

        self::assertSame($role, $role->givePermission($permission));
        self::assertSame($role, $role->givePermissionTo('posts:edit'));
        self::assertSame($role, $role->syncPermissions(['posts:edit']));
        self::assertSame([$permission->id], DB::table('role_permissions')->pluck('permission_id')->all());
        Event::assertDispatchedTimes(PermissionGranted::class, 1);

        self::assertSame($role, $role->revokePermission('posts:edit'));
        self::assertSame($role, $role->revokePermissionTo($permission));
        self::assertSame(0, DB::table('role_permissions')->count());
        Event::assertDispatchedTimes(PermissionRevoked::class, 1);
    }

    /**
     * A permission granted until an expiry stops counting the moment it passes,
     * and leaves the relation with it; the alias and a sync pass the expiry on,
     * the sync re-arming an expired grant.
     *
     * @return void
     */
    public function testAPermissionGrantedUntilAnExpiryLapses(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        $role = Role::query()->create(['name' => 'editor']);
        $edit = Permission::query()->create(['name' => 'posts:edit']);
        $read = Permission::query()->create(['name' => 'posts:read']);

        $role->givePermission($edit, Carbon::parse('2026-07-01 13:00:00'));
        $role->givePermissionTo($read, Carbon::parse('2026-07-01 14:00:00'));

        self::assertSame('2026-07-01 13:00:00', self::expiryOf($edit));
        self::assertSame('2026-07-01 14:00:00', self::expiryOf($read));

        Carbon::setTestNow('2026-07-01 13:00:00');

        self::assertSame(['posts:read'], $role->getPermissions());
        self::assertSame(['posts:read'], $role->permissions()->pluck('name')->all());

        $role->syncPermissions([$edit, $read], Carbon::parse('2026-07-02 12:00:00'));

        self::assertSame('2026-07-02 12:00:00', self::expiryOf($edit));
        self::assertSame('2026-07-01 14:00:00', self::expiryOf($read));
    }

    /**
     * A sync through the role replaces its permissions and reports each change.
     *
     * @return void
     */
    public function testASyncReplacesThePermissions(): void
    {
        $role   = Role::query()->create(['name' => 'editor']);
        $kept   = Permission::query()->create(['name' => 'posts:edit']);
        $gone   = Permission::query()->create(['name' => 'posts:delete']);
        $joined = Permission::query()->create(['name' => 'posts:create']);

        $role->givePermission($kept)->givePermission($gone);

        Event::fake([PermissionGranted::class, PermissionRevoked::class]);

        $role->syncPermissions([$kept, $joined]);

        self::assertEqualsCanonicalizing(['posts:create', 'posts:edit'], $role->getPermissions());
        Event::assertDispatched(PermissionGranted::class, static fn (PermissionGranted $event): bool => self::refersTo($event->permission, $joined));
        Event::assertDispatched(PermissionRevoked::class, static fn (PermissionRevoked $event): bool => self::refersTo($event->permission, $gone));
    }

    /**
     * A raw relation write bypasses the role service, so it reports nothing.
     *
     * @return void
     */
    public function testARawRelationWriteReportsNothing(): void
    {
        $role       = Role::query()->create(['name' => 'editor']);
        $permission = Permission::query()->create(['name' => 'posts:edit']);

        Event::fake([PermissionGranted::class]);

        $role->permissions()->attach($permission->id);

        self::assertSame(1, DB::table('role_permissions')->count());
        Event::assertNotDispatched(PermissionGranted::class);
    }

    /**
     * Without the role service bound, a write is refused rather than lost.
     *
     * @return void
     */
    public function testRefusesAWriteWithoutTheRoleService(): void
    {
        $role = Role::query()->create(['name' => 'editor']);

        unset($this->app[RoleService::class]);

        $this->expectExceptionObject(new \LogicException('The authorization role service is not bound; register the package\'s service provider.'));

        $role->givePermission('posts:edit');
    }

    /**
     * Return the expiry of the role permission row for the permission.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return string|null
     */
    private static function expiryOf(Permission $permission): ?string
    {
        /** @var string|null */
        return DB::table('role_permissions')->where('permission_id', $permission->id)->value('expires_at');
    }
}
