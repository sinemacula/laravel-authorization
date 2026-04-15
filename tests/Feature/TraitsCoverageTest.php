<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Traits\HasPermissions;
use SineMacula\Laravel\Authorization\Traits\HasPolicies;
use SineMacula\Laravel\Authorization\Traits\HasRoles;
use Tests\Feature\Stubs\StubAuthorizable;
use Tests\TestCase;

/**
 * Coverage-focused feature tests that exercise the trait helpers not
 * already covered by the manager-driven feature suite.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(HasRoles::class)]
#[CoversTrait(HasPermissions::class)]
#[CoversTrait(HasPolicies::class)]
final class TraitsCoverageTest extends TestCase
{
    /**
     * syncPermissions replaces the direct permission set.
     *
     * @return void
     */
    public function testSyncPermissionsReplacesSet(): void
    {
        Permission::create(['id' => '01J0000000000000000PERMA1', 'name' => 'a:do', 'guard_name' => 'web']);
        Permission::create(['id' => '01J0000000000000000PERMA2', 'name' => 'b:do', 'guard_name' => 'web']);
        Permission::create(['id' => '01J0000000000000000PERMA3', 'name' => 'c:do', 'guard_name' => 'web']);

        $user = StubAuthorizable::create(['id' => '01J0000000000000000USRSP1']);

        $user->syncPermissions(['a:do', 'b:do']);
        self::assertSame(['a:do', 'b:do'], self::sorted($user->fresh()?->getPermissions() ?? []));

        $user->syncPermissions(['c:do']);
        self::assertSame(['c:do'], $user->fresh()?->getPermissions());
    }

    /**
     * syncPolicies replaces the policy attachment set.
     *
     * @return void
     */
    public function testSyncPoliciesReplacesSet(): void
    {
        $first = Policy::create([
            'id'       => '01J000000000000000POLSP1',
            'name'     => 'first',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['x']]]],
        ]);
        $second = Policy::create([
            'id'       => '01J000000000000000POLSP2',
            'name'     => 'second',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['y']]]],
        ]);

        $user = StubAuthorizable::create(['id' => '01J000000000000000USRSP2']);

        $user->syncPolicies([$first, $second]);
        self::assertCount(2, $user->fresh()?->policies()->get() ?? []);

        $user->syncPolicies([$second]);
        $names = $user->fresh()?->policies()->pluck('name')->all() ?? [];
        self::assertSame(['second'], $names);
    }

    /**
     * Passing model instances directly bypasses the database lookup path.
     *
     * @return void
     */
    public function testRoleAndPermissionAcceptModelInstances(): void
    {
        $role       = Role::create(['id' => '01J0000000000000000ROLEMA1', 'name' => 'mod', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => '01J0000000000000000PERMMA1', 'name' => 'mod:do', 'guard_name' => 'web']);

        $user = StubAuthorizable::create(['id' => '01J0000000000000000USRMA1']);

        $user->assignRole($role);
        $user->givePermission($permission);

        self::assertTrue($user->hasRole($role));
        self::assertTrue($user->hasPermission($permission));

        $user->revokePermission($permission);
        $user->revokeRole($role);

        self::assertFalse($user->fresh()?->hasRole($role));
        self::assertFalse($user->fresh()?->hasPermission($permission));
    }

    /**
     * Sort an array of strings.
     *
     * @param  array<int, string>  $values
     * @return array<int, string>
     */
    private static function sorted(array $values): array
    {
        \sort($values);

        return \array_values($values);
    }
}
