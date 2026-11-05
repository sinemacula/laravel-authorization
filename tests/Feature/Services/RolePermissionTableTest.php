<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\RolePermissionTable;
use Tests\Concerns\RecordsRowLocks;
use Tests\TestCase;

/**
 * Feature tests for the writer of the permissions one role carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RolePermissionTable::class)]
final class RolePermissionTableTest extends TestCase
{
    use RecordsRowLocks;

    /**
     * A grant attaches the permission through the role's relation, with its
     * expiry, and clears the relation the role had loaded.
     *
     * @return void
     */
    public function testAGrantAttachesThePermissionWithItsExpiry(): void
    {
        $role       = Role::query()->create(['name' => 'editor']);
        $permission = Permission::query()->create(['name' => 'posts:edit']);

        self::assertCount(0, $role->permissions);
        self::assertSame(GrantOutcome::GRANTED, (new RolePermissionTable($role))->grant($permission->id, Carbon::parse('2099-01-01 12:00:00'))->outcome);
        self::assertFalse($role->relationLoaded('permissions'));
        self::assertSame([[$role->id, $permission->id, '2099-01-01 12:00:00']], self::rows());
    }

    /**
     * A grant goes through the pivot, so a permission under another guard is
     * refused.
     *
     * @return void
     */
    public function testAGrantKeepsGuardParity(): void
    {
        $role       = Role::query()->create(['name' => 'editor', 'guard' => 'web']);
        $permission = Permission::query()->create(['name' => 'posts:edit', 'guard' => 'api']);

        $this->expectException(GuardMismatchException::class);

        (new RolePermissionTable($role))->grant($permission->id, null);
    }

    /**
     * A grant written by another transaction between the check and the
     * attachment is read back instead of raising.
     *
     * @return void
     */
    public function testAConcurrentDuplicateIsReadBack(): void
    {
        $role       = Role::query()->create(['name' => 'editor']);
        $permission = Permission::query()->create(['name' => 'posts:edit']);
        $written    = false;

        DB::listen(static function (QueryExecuted $query) use (&$written, $role, $permission): void {
            if ($written || !\str_contains($query->sql, 'exists')) {
                return;
            }

            $written = true;

            DB::table('role_permissions')->insert(['role_id' => $role->id, 'permission_id' => $permission->id]);
        });

        self::assertSame(GrantOutcome::UNCHANGED, (new RolePermissionTable($role))->grant($permission->id, null)->outcome);
        self::assertSame([[$role->id, $permission->id, null]], self::rows());
    }

    /**
     * A held grant, expired or not, is read under a row lock and only its own
     * row is rewritten.
     *
     * @return void
     */
    public function testAHeldGrantIsReadUnderALockAndRewrittenAlone(): void
    {
        $role       = Role::query()->create(['name' => 'editor']);
        $other      = Role::query()->create(['name' => 'author']);
        $permission = Permission::query()->create(['name' => 'posts:edit']);
        $sibling    = Permission::query()->create(['name' => 'posts:read']);
        $table      = new RolePermissionTable($role);

        $table->grant($permission->id, Carbon::parse('2000-01-01 00:00:00'));
        $table->grant($sibling->id, null);
        (new RolePermissionTable($other))->grant($permission->id, null);

        $locks = $this->recordRowLocks();

        self::assertSame(GrantOutcome::REARMED, $table->grant($permission->id, Carbon::parse('2099-01-01 00:00:00'))->outcome);
        self::assertSame([['role_permissions', [$role->id, $permission->id]]], $locks->getArrayCopy());
        self::assertEqualsCanonicalizing([
            [$role->id, $permission->id, '2099-01-01 00:00:00'],
            [$role->id, $sibling->id, null],
            [$other->id, $permission->id, null],
        ], self::rows());
    }

    /**
     * Return every role permission row as its role, permission and expiry.
     *
     * @return list<array{string, string, string|null}>
     */
    private static function rows(): array
    {
        /** @var list<array{string, string, string|null}> */
        return DB::table('role_permissions')
            ->get(['role_id', 'permission_id', 'expires_at'])
            ->map(static fn (object $row): array => \array_values((array) $row))
            ->all();
    }
}
