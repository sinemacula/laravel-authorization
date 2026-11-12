<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Database\Query\JoinClause;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\GrantRelation;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\NumberedIdentity;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the grantee's relation onto its grants, which binds the
 * grantee's key as a string, alone and eager-loaded, and reads the rows given
 * in place of the grant table, while writing to the table itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantRelation::class)]
final class GrantRelationTest extends TestCase
{
    /** @var list<string> The permission grant table and its keys, as a grantee's permissions relation names them. */
    private const array PERMISSION_GRANTS = ['authorizable_permissions', 'authorizable_id', 'permission_id', 'id', 'id'];

    /**
     * One grantee's grants are read by its key as a string and its morph type.
     *
     * @return void
     */
    public function testAGranteesKeyIsBoundAsAString(): void
    {
        $user = NumberedIdentity::create(['name' => 'Ada']);

        $user->assignRole(Role::create(['name' => 'editor']));
        StubIdentity::create(['id' => (string) $user->id])->assignRole(Role::create(['name' => 'other']));

        $relation = $user->roles();

        self::assertInstanceOf(GrantRelation::class, $relation);
        self::assertSame([(string) $user->id, $user->getMorphClass()], \array_slice($relation->getQuery()->getQuery()->getRawBindings()['where'], 0, 2));
        self::assertSame(['editor'], $relation->pluck('name')->all());
    }

    /**
     * An eager load binds every grantee's key as a string, matches each grant
     * to its grantee, and leaves another type's grants with the same key out.
     *
     * @return void
     */
    public function testAnEagerLoadBindsEveryKeyAsAString(): void
    {
        $first  = NumberedIdentity::create(['name' => 'Ada']);
        $second = NumberedIdentity::create(['name' => 'Grace']);

        $first->assignRole(Role::create(['name' => 'editor']));
        StubIdentity::create(['id' => (string) $second->id])->assignRole(Role::create(['name' => 'other']));

        DB::flushQueryLog();
        DB::enableQueryLog();

        $loaded = NumberedIdentity::query()->with('roles')->orderBy('id')->get();

        $bindings = \array_merge(...\array_column(DB::getQueryLog(), 'bindings'));

        DB::disableQueryLog();

        self::assertContains((string) $first->id, $bindings);
        self::assertContains((string) $second->id, $bindings);
        self::assertNotContains($first->id, $bindings);
        self::assertSame([['editor'], []], $loaded->map(static fn (NumberedIdentity $user): array => $user->roles->pluck('name')->all())->all());
    }

    /**
     * Given rows to read in place of the grant table, the relation reads them
     * under the table's name, alone, eager-loaded and as an existence check,
     * while a write through it goes to the table; without, it reads the table.
     *
     * @return void
     */
    public function testRowsGivenAreReadInPlaceOfTheTable(): void
    {
        $user       = StubIdentity::create(['id' => 'user-1']);
        $permission = Permission::create(['name' => 'posts:read']);
        $other      = Permission::create(['name' => 'posts:edit']);
        $columns    = ['permission_id', 'authorizable_type', 'authorizable_id', 'tenant_type', 'tenant_id', 'application', 'expires_at', 'created_at', 'updated_at'];
        $rows       = DB::table('authorizable_permissions')->select($columns)
            ->unionAll(DB::query()->selectRaw('?, ?, ?, null, null, null, null, ?, ?', [$other->id, $user->getMorphClass(), 'user-1', Carbon::now(), Carbon::now()]));
        $relation = static fn (): GrantRelation => (new GrantRelation($permission->newQuery(), $user, 'authorizable', ...self::PERMISSION_GRANTS))
            ->readingRows($rows)
            ->withTimestamps();

        $relation()->attach($permission->id);

        self::assertSame(1, DB::table('authorizable_permissions')->count());
        self::assertSame(['posts:read', 'posts:edit'], $relation()->orderBy('name', 'desc')->pluck('name')->all());
        self::assertSame(['posts:read'], $user->permissions()->pluck('name')->all());
        self::assertStringContainsString('join (', $relation()->getRelationExistenceQuery(Permission::query(), StubIdentity::query())->toSql());
        self::assertStringContainsString('join (', $relation()->toSql());
        self::assertStringNotContainsString('join (', $user->permissions()->toSql());
        self::assertCount(1, $relation()->getQuery()->getQuery()->joins ?? []);

        $plain = new GrantRelation($permission->newQuery(), $user, 'authorizable', ...self::PERMISSION_GRANTS);

        self::assertSame($plain, $plain->readingRows(null));
        self::assertSame(['authorizable_permissions'], \array_map(static fn (JoinClause $join): mixed => $join->table, $plain->getQuery()->getQuery()->joins ?? []));
    }
}
