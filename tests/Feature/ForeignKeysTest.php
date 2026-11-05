<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the foreign keys the shipped migrations declare: the parent
 * role's self-referencing key, which refuses to delete a parent with children,
 * and the keys that delete a role's, permission's or policy's grants and
 * role-permission rows with it. The test connection enforces foreign keys on
 * every database, SQLite included, so each delete is the database's work, not
 * the package's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversNothing]
final class ForeignKeysTest extends TestCase
{
    /**
     * Every foreign key, by table and column, with the table and column it
     * references and what a delete there does.
     *
     * @return iterable<string, array{string, string, string, string}>
     */
    public static function foreignKeys(): iterable
    {
        yield 'parent role' => ['roles', 'parent_id', 'roles', 'restrict'];
        yield 'role of a role permission' => ['role_permissions', 'role_id', 'roles', 'cascade'];
        yield 'permission of a role permission' => ['role_permissions', 'permission_id', 'permissions', 'cascade'];
        yield 'granted role' => ['authorizable_roles', 'role_id', 'roles', 'cascade'];
        yield 'granted permission' => ['authorizable_permissions', 'permission_id', 'permissions', 'cascade'];
        yield 'attached policy' => ['authorizable_policies', 'policy_id', 'policies', 'cascade'];
    }

    /**
     * The table declares the foreign key, referencing the primary key of the
     * other table, with the given delete rule.
     *
     * @param  string  $table
     * @param  string  $column
     * @param  string  $references
     * @param  string  $onDelete
     * @return void
     */
    #[DataProvider('foreignKeys')]
    public function testTheForeignKeyIsDeclared(string $table, string $column, string $references, string $onDelete): void
    {
        $matching = \array_values(\array_filter(
            Schema::getForeignKeys($table),
            static fn (array $key): bool => $key['columns'] === [$column],
        ));

        self::assertCount(1, $matching);
        self::assertSame($references, $matching[0]['foreign_table']);
        self::assertSame(['id'], $matching[0]['foreign_columns']);
        self::assertSame($onDelete, \strtolower((string) $matching[0]['on_delete']));
    }

    /**
     * The database refuses to delete a parent role with children, however the
     * delete is made (D18).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletingAParentRoleWithChildrenIsRefused(): void
    {
        $parent = Role::query()->create(['name' => 'admin']);
        $child  = Role::query()->create(['name' => 'editor', 'parent_id' => $parent->id]);

        try {
            DB::transaction(static fn (): int => DB::table('roles')->where('id', $parent->id)->delete());
            self::fail('A parent with children was deleted.');
        } catch (QueryException) {
            self::assertSame($parent->id, DB::table('roles')->where('id', $child->id)->value('parent_id'));
        }
    }

    /**
     * A parent that does not exist is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAParentThatDoesNotExistIsRefused(): void
    {
        $refused = false;

        try {
            DB::transaction(static fn (): bool => DB::table('roles')->insert(['id' => (string) Str::uuid(), 'name' => 'editor', 'parent_id' => (string) Str::uuid()]));
        } catch (QueryException) {
            $refused = true;
        }

        self::assertTrue($refused);
    }

    /**
     * Deleting a role, a permission or a policy deletes its grants and its
     * role-permission rows with it.
     *
     * @return void
     */
    public function testDeletingAGrantedRowDeletesItsGrants(): void
    {
        $role       = Role::query()->create(['name' => 'editor']);
        $permission = Permission::query()->create(['name' => 'posts:edit']);
        $policy     = Policy::query()->create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]);
        $identity   = StubIdentity::query()->create(['id' => (string) Str::uuid()]);

        $role->permissions()->attach($permission);
        $identity->assignRole($role);
        $identity->givePermission($permission);
        $identity->attachPolicy($policy);

        DB::table('roles')->where('id', $role->id)->delete();
        DB::table('permissions')->where('id', $permission->id)->delete();
        DB::table('policies')->where('id', $policy->id)->delete();

        foreach (['role_permissions', 'authorizable_roles', 'authorizable_permissions', 'authorizable_policies'] as $table) {
            self::assertSame(0, DB::table($table)->count(), $table);
        }
    }
}
