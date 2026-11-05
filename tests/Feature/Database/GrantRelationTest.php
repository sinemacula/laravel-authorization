<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\GrantRelation;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\NumberedIdentity;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the grantee's relation onto its grants, which binds the
 * grantee's key as a string, alone and eager-loaded.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantRelation::class)]
final class GrantRelationTest extends TestCase
{
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
        self::assertSame([(string) $user->id, $user->getMorphClass()], \array_slice($relation->getBindings(), 0, 2));
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
}
