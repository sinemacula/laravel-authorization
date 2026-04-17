<?php

declare(strict_types = 1);

namespace Tests\Integration;

use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Traits\HasRoles;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\TestCase;

/**
 * Integration tests covering polymorphic identity support — two
 * unrelated models share the same role and produce identical
 * decisions without model-class collisions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
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
        $role       = Role::create(['id' => 'f7e19d53-dd4e-49a2-8f1e-288453bffc75', 'name' => 'shared', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => '9044baf5-429e-4b72-836a-73ca15cf8f8a', 'name' => 'thing:do', 'guard_name' => 'web']);
        $role->permissions()->attach($permission->getKey());

        $first  = StubIdentity::create(['id' => '3a7d2eb1-f646-4131-897c-8d0a1a6ecaad']);
        $second = StubSecondIdentity::create(['id' => 'eb79f1c6-3794-4840-8f3c-8a8421db18b8']);

        $first->assignRole('shared');
        $second->assignRole('shared');

        self::assertTrue(Authorization::for($first)->can('thing:do'));
        self::assertTrue(Authorization::for($second)->can('thing:do'));

        // Polymorphic types on the pivot remain distinct.
        self::assertSame(
            [StubIdentity::class, StubSecondIdentity::class],
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

        return \array_values($types); // @phpstan-ignore return.type, arrayValues.list (test stub loosens return type for fixture convenience; test coerces numeric-indexed list intentionally)
    }
}
