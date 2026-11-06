<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\LiveGrants;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\TestCase;

/**
 * Feature tests for the limit to the grant rows that still count.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LiveGrants::class)]
final class LiveGrantsTest extends TestCase
{
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
     * Rows with no expiry, or an expiry still ahead, count; a row whose expiry
     * is now or has passed does not, and the limit is grouped, so it narrows
     * what the query already selects rather than widening it.
     *
     * @return void
     */
    public function testOnlyRowsWhoseExpiryIsAheadCount(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        $role  = Role::query()->create(['name' => 'editor']);
        $other = Role::query()->create(['name' => 'author']);

        foreach (['forever' => null, 'ahead' => '2026-07-01 12:00:01', 'now' => '2026-07-01 12:00:00', 'passed' => '2026-07-01 11:00:00'] as $name => $expiresAt) {
            DB::table('role_permissions')->insert([
                'role_id'       => $role->id,
                'permission_id' => Permission::query()->create(['name' => "posts:{$name}"])->id,
                'expires_at'    => $expiresAt,
            ]);
        }

        DB::table('role_permissions')->insert(['role_id' => $other->id, 'permission_id' => Permission::query()->create(['name' => 'posts:other'])->id]);

        $query = DB::table('role_permissions')
            ->join('permissions', 'permissions.id', '=', 'role_permissions.permission_id')
            ->where('role_permissions.role_id', $role->id);

        self::assertSame($query, LiveGrants::only($query, 'role_permissions'));
        self::assertEqualsCanonicalizing(['posts:forever', 'posts:ahead'], $query->pluck('permissions.name')->all());
    }
}
