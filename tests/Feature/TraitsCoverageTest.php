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
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Coverage-focused feature tests that exercise the trait helpers not
 * already covered by the manager-driven feature suite.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
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
        Permission::create(['id' => '844d9762-e1d9-490e-8d0d-d0d856689036', 'name' => 'a:do', 'guard_name' => 'web']);
        Permission::create(['id' => '50b2af60-b3ff-4d51-8002-f923cf97d9e3', 'name' => 'b:do', 'guard_name' => 'web']);
        Permission::create(['id' => '0b1f39a5-ea11-4390-8143-3a2f85811785', 'name' => 'c:do', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => 'e1be5db2-7198-4edc-8269-d30117f6dc17']);

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
            'id'       => '4aa6282d-a2ea-43ac-8d1e-024268ccd29f',
            'name'     => 'first',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['x']]]],
        ]);
        $second = Policy::create([
            'id'       => '986f4835-9937-4437-8b2b-7d741d2a8b7a',
            'name'     => 'second',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['y']]]],
        ]);

        $user = StubIdentity::create(['id' => 'e23d07d5-5086-4f02-8f8c-3d25541a6a0f']);

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
        $role       = Role::create(['id' => '9e8c50ef-c078-4e48-8085-a15e365f1b34', 'name' => 'mod', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => '76186991-c4cc-42cb-8ef2-f83d7c13e46b', 'name' => 'mod:do', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => '1ba57f4e-f9b6-4eaf-8cd7-72a9dae46814']);

        $user->assignRole($role);
        $user->givePermission($permission);

        self::assertTrue($user->hasRole($role));
        self::assertTrue($user->hasPermission($permission));

        $user->revokePermission($permission);
        $user->revokeRole($role);

        self::assertFalse($user->fresh()?->hasRole($role)); // @phpstan-ignore nullsafe.neverNull (fresh() non-null after persistence)
        self::assertFalse($user->fresh()?->hasPermission($permission)); // @phpstan-ignore nullsafe.neverNull (fresh() always hydrates after persistence in this test context)
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

        return \array_values($values); // @phpstan-ignore arrayValues.list (numeric-indexed list coerce)
    }
}
