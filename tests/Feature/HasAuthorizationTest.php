<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Events\Grantee\PermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Grantee\PolicyDetached;
use SineMacula\Laravel\Authorization\Events\Grantee\RoleRevoked;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Feature\Stubs\NumberedGrantee;
use Tests\Feature\Stubs\StubGrantee;
use Tests\TestCase;

/**
 * Feature tests for the composed grantee trait: a grantee is active unless it
 * says otherwise, its grants go when it is deleted, and integer keys work on
 * every supported database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(HasAuthorization::class)]
final class HasAuthorizationTest extends TestCase
{
    use ActsAsTenant, ReadsDispatchedEvents;

    /**
     * A grantee is active unless the model says otherwise.
     *
     * @return void
     */
    public function testAGranteeIsActiveByDefault(): void
    {
        self::assertTrue(StubGrantee::create(['id' => 'user-1'])->isAuthorizationActive());
    }

    /**
     * Deleting a grantee removes its grants, and only its own.
     *
     * @return void
     */
    public function testDeletingAGranteeRemovesItsGrants(): void
    {
        $user  = StubGrantee::create(['id' => 'user-1']);
        $other = StubGrantee::create(['id' => 'user-2']);
        $role  = Role::create(['name' => 'editor']);

        $user->assignRole($role);
        $other->assignRole($role);
        $user->givePermission(Permission::create(['name' => 'posts:edit']));

        $user->delete();

        self::assertSame(['user-2'], DB::table('authorizable_roles')->pluck('authorizable_id')->all());
        self::assertSame(0, DB::table('authorizable_permissions')->count());
    }

    /**
     * Deleting a grantee while scoped to one tenant revokes its grants in every
     * tenant and application, a role another tenant owns among them, and
     * reports each.
     *
     * @return void
     */
    public function testDeletingAGranteeInATenantRevokesItsGrantsEverywhere(): void
    {
        $tenantA = self::createTenant('tenant-a');
        $tenantB = self::createTenant('tenant-b');
        $user    = StubGrantee::create(['id' => 'user-1']);

        $user->assignRole(Role::create(['name' => 'editor']), tenant: $tenantA);
        $user->assignRole(Role::create(['name' => 'b-role'] + self::ownedBy($tenantB)), tenant: $tenantB);
        $user->givePermission(Permission::create(['name' => 'posts:edit']));
        $user->attachPolicy(Policy::create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]), application: 'admin');

        $this->actAsTenant($tenantA);

        Event::fake([RoleRevoked::class, PermissionRevoked::class, PolicyDetached::class]);

        $user->delete();

        $events  = [...self::dispatchedEvents(RoleRevoked::class), ...self::dispatchedEvents(PermissionRevoked::class), ...self::dispatchedEvents(PolicyDetached::class)];
        $revoked = \array_map(
            static fn (PermissionRevoked|PolicyDetached|RoleRevoked $event): array => [$event->name, $event->scope->tenant?->id, $event->scope->application],
            $events,
        );

        self::assertEqualsCanonicalizing([['editor', 'tenant-a', null], ['b-role', 'tenant-b', null], ['posts:edit', null, null], ['readers', null, 'admin']], $revoked);

        foreach (['authorizable_roles', 'authorizable_permissions', 'authorizable_policies'] as $table) {
            self::assertSame(0, DB::table($table)->count(), $table);
        }
    }

    /**
     * A soft delete keeps the grants, so restoring the grantee restores its
     * access; a force delete removes them.
     *
     * @return void
     */
    public function testASoftDeleteKeepsTheGrantsUntilAForceDelete(): void
    {
        $user = NumberedGrantee::create(['name' => 'Ada']);

        $user->assignRole(Role::create(['name' => 'editor']));
        $user->delete();

        self::assertSame(1, DB::table('authorizable_roles')->count());

        $user->restore(); // @phpstan-ignore staticMethod.dynamicCall

        self::assertSame(['editor'], $user->getRoles());

        $user->forceDelete();

        self::assertSame(0, DB::table('authorizable_roles')->count());
    }

    /**
     * A grantee with an integer key holds and resolves roles, permissions and
     * policies, alone and eager-loaded alongside others.
     *
     * @return void
     */
    public function testAnIntegerKeyedGranteeResolvesItsGrants(): void
    {
        $first  = NumberedGrantee::create(['name' => 'Ada']);
        $second = NumberedGrantee::create(['name' => 'Grace']);
        $role   = Role::create(['name' => 'editor']);

        $role->givePermission(Permission::create(['name' => 'posts:edit']));
        $first->assignRole($role);
        $second->givePermission(Permission::create(['name' => 'posts:read']));
        $second->attachPolicy(Policy::create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]));

        self::assertSame(['editor'], $first->getRoles());
        self::assertSame(['posts:edit'], $first->getPermissions());
        self::assertSame(['posts:read'], $second->getPermissions());
        self::assertSame(['readers'], \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $second->getPolicies()));

        $loaded = NumberedGrantee::query()->with(['roles', 'permissions', 'policies'])->orderBy('id')->get();

        self::assertSame([['editor'], []], $loaded->map(static fn (NumberedGrantee $user): array => $user->roles->pluck('name')->all())->all());
        self::assertSame([[], ['posts:read']], $loaded->map(static fn (NumberedGrantee $user): array => $user->permissions->pluck('name')->all())->all());
        self::assertSame([[], ['readers']], $loaded->map(static fn (NumberedGrantee $user): array => $user->policies->pluck('name')->all())->all());
    }
}
