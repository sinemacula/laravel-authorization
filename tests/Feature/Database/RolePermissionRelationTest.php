<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\RolePermissionRelation;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\TestCase;

/**
 * Feature tests for `RolePermissionRelation`, what the relation between a role
 * and the permissions it carries reads from either side: the configured table
 * and only the rows whose grant has not expired.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RolePermissionRelation::class)]
final class RolePermissionRelationTest extends TestCase
{
    /**
     * The table is the one the config names.
     *
     * @return void
     */
    public function testTheTableIsTheOneTheConfigNames(): void
    {
        self::assertSame('role_permissions', RolePermissionRelation::table());

        config(['authorization.tables.role_permissions' => 'carried']);

        self::assertSame('carried', RolePermissionRelation::table());
    }

    /**
     * The relation, from either side, leaves out a row whose grant has expired,
     * and keeps one with no expiry or one still to come.
     *
     * @return void
     */
    public function testEitherSideReadsOnlyTheLiveRows(): void
    {
        Carbon::setTestNow('2026-06-01 12:00:00');

        $role = Role::query()->create(['name' => 'editor']);

        foreach (['posts:read' => null, 'posts:edit' => '2026-07-01 00:00:00', 'posts:delete' => '2026-05-01 00:00:00'] as $name => $expiry) {
            $permission = Permission::query()->create(['name' => $name]);

            DB::table('role_permissions')->insert(['role_id' => $role->getKey(), 'permission_id' => $permission->getKey(), 'expires_at' => $expiry]);
        }

        $live = $role->permissions()->orderBy('name')->pluck('name')->all();

        Carbon::setTestNow();

        self::assertSame(['posts:edit', 'posts:read'], $live);
        self::assertSame([], Permission::query()->where('name', 'posts:delete')->sole()->roles()->get()->all());
        self::assertSame(['editor'], Permission::query()->where('name', 'posts:read')->sole()->roles()->pluck('name')->all());
    }
}
