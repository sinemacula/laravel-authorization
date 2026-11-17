<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\Support\SpatieRows;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\DeclaresPermissions;
use Tests\TestCase;

/**
 * Feature tests for `SpatieRows`: the rows a Spatie import reuses, and the
 * changes it would make to a system role's permissions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(SpatieRows::class)]
final class SpatieRowsTest extends TestCase
{
    use DeclaresPermissions;

    /**
     * The row reused is the one of the name and guard the owner holds, the
     * platform's for no owner.
     *
     * @return void
     */
    public function testTheRowOfTheNameGuardAndOwnerIsReused(): void
    {
        $tenant   = new Reference('stub_tenant', 'tenant-a');
        $platform = Role::query()->create(['name' => 'admin', 'guard' => 'web']);
        $owned    = Role::query()->withoutGlobalScopes()->create(['name' => 'admin', 'guard' => 'web', ...self::ownedBy($tenant)]);

        self::assertSame($platform->id, SpatieRows::owned('role', 'admin', 'web', null)?->getKey());
        self::assertSame($owned->id, SpatieRows::owned('role', 'admin', 'web', $tenant)?->getKey());
        self::assertNull(SpatieRows::owned('role', 'admin', 'api', null));
        self::assertNull(SpatieRows::owned('role', 'admin', 'web', new Reference('stub_tenant', 'tenant-b')));
    }

    /**
     * A system role the import reuses gains each Spatie permission it does not
     * hold forever, new or held with an expiry, by role name; a permission the
     * import skips, a role that is not system and a row naming no imported role
     * or permission change nothing.
     *
     * @return void
     */
    public function testTheChangesToEachSystemRoleAreListed(): void
    {
        $tenant = new Reference('stub_tenant', 'tenant-a');
        $admin  = Role::query()->create(['name' => 'admin', 'guard' => 'web', 'is_system' => true]);
        $owner  = Role::query()->withoutGlobalScopes()->create(['name' => 'owner', 'guard' => 'web', 'is_system' => true, ...self::ownedBy($tenant)]);
        $kept   = Permission::query()->create(['name' => 'posts:read', 'guard' => 'web']);
        $dated  = Permission::query()->create(['name' => 'posts:edit', 'guard' => 'web']);

        Role::query()->create(['name' => 'editor', 'guard' => 'web']);

        $admin->permissions()->attach($kept->id, ['expires_at' => null]);
        $admin->permissions()->attach($dated->id, ['expires_at' => Carbon::parse('2030-01-01')]);
        $owner->permissions()->attach($kept->id, ['expires_at' => null]);

        $roles = [
            ['id' => 1, 'name' => 'admin', 'guard_name' => 'web'],
            ['id' => 2, 'name' => 'owner', 'guard_name' => 'web', 'team_id' => 'tenant-a'],
            ['id' => 3, 'name' => 'editor', 'guard_name' => 'web'],
        ];

        $permissions = [
            ['id' => 1, 'name' => 'posts:read', 'guard_name' => 'web'],
            ['id' => 2, 'name' => 'posts:edit', 'guard_name' => 'web'],
            ['id' => 3, 'name' => 'posts:create', 'guard_name' => 'web'],
            ['id' => 4, 'name' => 'posts:*', 'guard_name' => 'web'],
            ['id' => 5, 'name' => 'not valid', 'guard_name' => 'web'],
        ];

        $rolePermissions = [
            ['role_id' => 1, 'permission_id' => 1],
            ['role_id' => 1, 'permission_id' => 2],
            ['role_id' => 1, 'permission_id' => 3],
            ['role_id' => 1, 'permission_id' => 4],
            ['role_id' => 1, 'permission_id' => 5],
            ['role_id' => 1, 'permission_id' => 9],
            ['role_id' => 2, 'permission_id' => 1],
            ['role_id' => 2, 'permission_id' => 3],
            ['role_id' => 3, 'permission_id' => 3],
            ['role_id' => 9, 'permission_id' => 3],
        ];

        $tenantOf = static fn (array $row): ?Reference => \is_string($row['team_id'] ?? null) ? new Reference('stub_tenant', $row['team_id']) : null;

        self::assertSame(
            ['admin' => ['posts:edit', 'posts:create'], 'owner' => ['posts:create']],
            SpatieRows::systemRoleChanges($roles, $permissions, $rolePermissions, $tenantOf),
        );
    }

    /**
     * A permission the code does not declare is skipped by the import, so it
     * is no change to a system role.
     *
     * @return void
     */
    public function testAnUndeclaredPermissionIsNoChange(): void
    {
        $this->declarePermissions('posts:read');

        Role::query()->create(['name' => 'admin', 'guard' => 'web', 'is_system' => true]);

        $changes = SpatieRows::systemRoleChanges(
            [['id' => 1, 'name' => 'admin', 'guard_name' => 'web']],
            [['id' => 1, 'name' => 'posts:read', 'guard_name' => 'web'], ['id' => 2, 'name' => 'posts:purge', 'guard_name' => 'web']],
            [['role_id' => 1, 'permission_id' => 1], ['role_id' => 1, 'permission_id' => 2]],
            static fn (array $row): ?Reference => null,
        );

        self::assertSame(['admin' => ['posts:read']], $changes);
    }

    /**
     * With no system role among the roles reused, nothing changes.
     *
     * @return void
     */
    public function testNoSystemRoleMeansNoChanges(): void
    {
        Role::query()->create(['name' => 'admin', 'guard' => 'web']);

        $changes = SpatieRows::systemRoleChanges(
            [['id' => 1, 'name' => 'admin', 'guard_name' => 'web']],
            [['id' => 1, 'name' => 'posts:read', 'guard_name' => 'web']],
            [['role_id' => 1, 'permission_id' => 1]],
            static fn (array $row): ?Reference => null,
        );

        self::assertSame([], $changes);
    }

    /**
     * Return the tenant columns of a row the tenant owns.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return array{tenant_type: string, tenant_id: string}
     */
    private static function ownedBy(Reference $tenant): array
    {
        return ['tenant_type' => $tenant->type, 'tenant_id' => $tenant->id];
    }
}
