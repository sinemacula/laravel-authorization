<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\HasRoles;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\StubGrantee;
use Tests\Feature\Stubs\StubSecondGrantee;
use Tests\TestCase;

/**
 * Integration tests covering polymorphic grantee support — two unrelated models
 * share the same role and produce identical decisions without model-class
 * collisions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversTrait(HasRoles::class)]
final class PolymorphicGranteeTest extends TestCase
{
    /**
     * Two unrelated grantee models share a role and are granted the same
     * permission without any model-class collisions.
     *
     * @return void
     */
    public function testTwoDistinctGranteeModelsShareARole(): void
    {
        $role       = Role::create(['id' => 'f7e19d53-dd4e-49a2-8f1e-288453bffc75', 'name' => 'shared', 'guard' => 'web']);
        $permission = Permission::create(['id' => '9044baf5-429e-4b72-836a-73ca15cf8f8a', 'name' => 'thing:do', 'guard' => 'web']);
        $role->permissions()->attach($permission->getKey());

        $first  = StubGrantee::create(['id' => '3a7d2eb1-f646-4131-897c-8d0a1a6ecaad']);
        $second = StubSecondGrantee::create(['id' => 'eb79f1c6-3794-4840-8f3c-8a8421db18b8']);

        $first->assignRole('shared');
        $second->assignRole('shared');

        self::assertTrue(Authorization::for($first)->can('thing:do'));
        self::assertTrue(Authorization::for($second)->can('thing:do'));

        // Polymorphic types on the pivot remain distinct.
        self::assertSame(
            [StubGrantee::class, StubSecondGrantee::class],
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
        $types = DB::table('authorizable_roles')
            ->select('authorizable_type')
            ->distinct()
            ->pluck('authorizable_type')
            ->all();

        \sort($types);

        // @phpstan-ignore-next-line return.type, arrayValues.list
        return \array_values($types);
    }
}
