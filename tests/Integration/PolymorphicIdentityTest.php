<?php

declare(strict_types = 1);

namespace Tests\Integration;

use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Traits\HasRoles;
use Tests\Feature\Stubs\StubAuthorizable;
use Tests\Feature\Stubs\StubSecondAuthorizable;
use Tests\TestCase;

/**
 * Integration tests covering the P0 "polymorphic identity support"
 * acceptance criterion — two unrelated models sharing the same role
 * and producing identical decisions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(HasRoles::class)]
final class PolymorphicIdentityTest extends TestCase
{
    /**
     * Two unrelated identity models share a role and are granted the
     * same permission without any model-class collisions.
     *
     * @return void
     */
    public function testTwoDistinctIdentityModelsShareARole(): void
    {
        $role       = Role::create(['id' => '01J0000000000000000ROLE01', 'name' => 'shared', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => '01J0000000000000000PERM01', 'name' => 'thing:do', 'guard_name' => 'web']);
        $role->permissions()->attach($permission->getKey());

        $first  = StubAuthorizable::create(['id' => '01J0000000000000000USR101']);
        $second = StubSecondAuthorizable::create(['id' => '01J0000000000000000USR102']);

        $first->assignRole('shared');
        $second->assignRole('shared');

        self::assertTrue(Authorization::for($first)->can('thing:do'));
        self::assertTrue(Authorization::for($second)->can('thing:do'));

        // Polymorphic types on the pivot remain distinct.
        self::assertSame(
            [StubAuthorizable::class, StubSecondAuthorizable::class],
            self::sortedTypes(),
        );
    }

    /**
     * Return the distinct polymorphic types recorded on the role pivot.
     *
     * @return array<int, string>
     */
    private static function sortedTypes(): array
    {
        $types = \Illuminate\Support\Facades\DB::table('authorizable_roles')
            ->select('authorizable_type')
            ->distinct()
            ->pluck('authorizable_type')
            ->all();

        \sort($types);

        return \array_values($types);
    }
}
