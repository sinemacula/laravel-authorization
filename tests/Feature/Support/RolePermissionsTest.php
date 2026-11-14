<?php

declare(strict_types = 1);

namespace Tests\Feature\Support;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\RolePermissions;
use Tests\Concerns\ActsAsTenant;
use Tests\TestCase;

/**
 * Feature tests for reading the permissions roles still carry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RolePermissions::class)]
final class RolePermissionsTest extends TestCase
{
    use ActsAsTenant;

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
     * The names each role carries are read in one query, keyed by the role, an
     * expired grant left out; no role reads nothing, without a query.
     *
     * @return void
     */
    public function testTheNamesEachRoleCarries(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        $editor = Role::create(['name' => 'editor']);
        $reader = Role::create(['name' => 'reader']);
        $empty  = Role::create(['name' => 'empty']);
        $read   = Permission::create(['name' => 'posts:read']);

        $editor->givePermission(Permission::create(['name' => 'posts:edit']));
        $editor->givePermission($read);
        $editor->givePermission(Permission::create(['name' => 'posts:delete']), Carbon::parse('2026-07-01 11:00:00'));
        $reader->givePermission($read);

        $carried = null;

        self::assertSame(1, self::queriesFor(static function () use ($editor, $reader, $empty, &$carried): void {
            $carried = RolePermissions::namesByRole([$editor->id, $reader->id, $empty->id]);
        }));
        self::assertIsArray($carried);
        self::assertEqualsCanonicalizing([$editor->id, $reader->id], \array_keys($carried));
        self::assertEqualsCanonicalizing(['posts:edit', 'posts:read'], $carried[$editor->id]);
        self::assertSame(['posts:read'], $carried[$reader->id]);
        self::assertSame(0, self::queriesFor(static fn (): array => RolePermissions::namesByRole([])));
        self::assertSame([], RolePermissions::namesByRole([]));
    }

    /**
     * The permissions the roles carry are named once each, with the seconds
     * until the nearest expiry still ahead, and no key or name by role unless
     * asked for.
     *
     * @return void
     */
    public function testTheCarriedPermissionsAndTheNearestExpiry(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        $editor = Role::create(['name' => 'editor']);
        $reader = Role::create(['name' => 'reader']);
        $read   = Permission::create(['name' => 'posts:read']);

        $editor->givePermission($read, Carbon::parse('2026-07-01 12:10:00'));
        $editor->givePermission(Permission::create(['name' => 'posts:list']));
        $editor->givePermission(Permission::create(['name' => 'posts:delete']), Carbon::parse('2026-07-01 11:00:00'));
        $reader->givePermission($read, Carbon::parse('2026-07-01 12:05:00'));

        $carried = null;

        self::assertSame(1, self::queriesFor(static function () use ($editor, $reader, &$carried): void {
            $carried = RolePermissions::carried([$editor->id, $reader->id]);
        }));
        self::assertNotNull($carried);
        self::assertEqualsCanonicalizing(['posts:read', 'posts:list'], $carried->names);
        self::assertCount(2, $carried->names);
        self::assertSame(300, $carried->expiresIn);
        self::assertNull($carried->byRole);
        self::assertNull(RolePermissions::carried([$editor->id, $reader->id], false)->byRole);
        self::assertSame(600, RolePermissions::carried([$editor->id])->expiresIn);

        $lister = Role::create(['name' => 'lister']);

        $lister->givePermission(Permission::create(['name' => 'posts:view']));

        self::assertNull(RolePermissions::carried([$lister->id])->expiresIn);

        $lister->givePermission(Permission::create(['name' => 'posts:export']), Carbon::parse('2026-07-01 12:05:00'));
        $lister->givePermission(Permission::create(['name' => 'posts:import']), Carbon::parse('2026-07-01 12:20:00'));

        self::assertSame(300, RolePermissions::carried([$lister->id])->expiresIn);
    }

    /**
     * Asked for, the key and name of each permission are read by the key of
     * each role carrying it, each once.
     *
     * @return void
     */
    public function testTheCarriedPermissionsByRole(): void
    {
        $editor = Role::create(['name' => 'editor']);
        $reader = Role::create(['name' => 'reader']);
        $read   = Permission::create(['name' => 'posts:read']);
        $edit   = Permission::create(['name' => 'posts:edit']);

        $editor->givePermission($read);
        $editor->givePermission($edit);
        $reader->givePermission($read);

        $carried = RolePermissions::carried([$editor->id, $reader->id], true);

        self::assertEqualsCanonicalizing(['posts:read', 'posts:edit'], $carried->names);
        self::assertNull($carried->expiresIn);
        self::assertSame([['id' => $read->id, 'name' => 'posts:read']], $carried->byRole[$reader->id] ?? null);
        self::assertEqualsCanonicalizing([['id' => $read->id, 'name' => 'posts:read'], ['id' => $edit->id, 'name' => 'posts:edit']], $carried->byRole[$editor->id] ?? null);
    }

    /**
     * No roles carry nothing, without a query, an empty list by role only when
     * asked for.
     *
     * @return void
     */
    public function testNoRolesCarryNothing(): void
    {
        self::assertSame(0, self::queriesFor(static fn (): array => RolePermissions::carried([], true)->names));

        $none   = RolePermissions::carried([]);
        $byRole = RolePermissions::carried([], true);

        self::assertSame([], $none->names);
        self::assertNull($none->expiresIn);
        self::assertNull($none->byRole);
        self::assertSame([], $byRole->byRole);
    }

    /**
     * The permissions are read through the permission model, so the tenant
     * scope hides another tenant's.
     *
     * @return void
     */
    public function testTheTenantScopeApplies(): void
    {
        $tenant = self::createTenant('t-2');
        $role   = Role::query()->withoutGlobalScope(TenantScope::class)->create(['name' => 'shared', 'guard' => 'web', ...self::ownedBy($tenant)]);

        $role->permissions()->attach(Permission::create(['name' => 'posts:read', 'guard' => 'web'])->id);
        $role->permissions()->attach(Permission::query()->withoutGlobalScope(TenantScope::class)->create(['name' => 'posts:own', 'guard' => 'web', ...self::ownedBy($tenant)])->id);

        self::assertSame(['posts:read'], RolePermissions::carried([$role->id])->names);
        self::assertSame([$role->id => ['posts:read']], RolePermissions::namesByRole([$role->id]));

        $this->actAsTenant($tenant);

        self::assertEqualsCanonicalizing(['posts:read', 'posts:own'], RolePermissions::carried([$role->id])->names);
        self::assertEqualsCanonicalizing(['posts:read', 'posts:own'], RolePermissions::namesByRole([$role->id])[$role->id] ?? []);
    }

    /**
     * Count the queries the work runs.
     *
     * @param  \Closure(): mixed  $work
     * @return int
     */
    private static function queriesFor(\Closure $work): int
    {
        DB::flushQueryLog();
        DB::enableQueryLog();

        $work();

        $count = \count(DB::getQueryLog());

        DB::disableQueryLog();

        return $count;
    }
}
