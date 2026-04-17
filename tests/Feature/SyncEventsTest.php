<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
use SineMacula\Laravel\Authorization\Events\Identity\IdentityPermissionGranted;
use SineMacula\Laravel\Authorization\Events\Identity\IdentityPermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Identity\IdentityPolicyAttached;
use SineMacula\Laravel\Authorization\Events\Identity\IdentityPolicyDetached;
use SineMacula\Laravel\Authorization\Events\Identity\IdentityRoleAssigned;
use SineMacula\Laravel\Authorization\Events\Identity\IdentityRoleRevoked;
use SineMacula\Laravel\Authorization\Events\Role\RolePermissionGranted;
use SineMacula\Laravel\Authorization\Events\Role\RolePermissionRevoked;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use SineMacula\Laravel\Authorization\Resolvers\NullTenantResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use SineMacula\Laravel\Authorization\Traits\HasPermissions;
use SineMacula\Laravel\Authorization\Traits\HasPolicies;
use SineMacula\Laravel\Authorization\Traits\HasRoleHierarchy;
use SineMacula\Laravel\Authorization\Traits\HasRoles;
use SineMacula\Laravel\Authorization\Traits\ManagesPermissions;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature coverage for the per-row events that `sync*` methods
 * dispatch (issue #56).
 *
 * Each `sync*` method on the trait triad and on `Role` consults
 * the delta returned by Eloquent's `sync()` and dispatches the
 * matching single-item event for every attached and detached
 * pivot row, so audit consumers receive the same per-row signal
 * they would for the corresponding `assignRole` / `givePermission`
 * / `attachPolicy` / role-side `givePermission` calls.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Role::class)]
#[CoversClass(RoleObserver::class)]
#[CoversClass(IdentityRoleAssigned::class)]
#[CoversClass(IdentityRoleRevoked::class)]
#[CoversClass(IdentityPermissionGranted::class)]
#[CoversClass(IdentityPermissionRevoked::class)]
#[CoversClass(IdentityPolicyAttached::class)]
#[CoversClass(IdentityPolicyDetached::class)]
#[CoversClass(RolePermissionGranted::class)]
#[CoversClass(RolePermissionRevoked::class)]
#[CoversClass(TenantScope::class)]
#[CoversClass(NullTenantResolver::class)]
#[CoversClass(ResolutionCacheContext::class)]
#[CoversClass(InvalidTenantException::class)]
#[CoversClass(InvalidTenantColumnsException::class)]
#[CoversClass(GuardScopedLookup::class)]
#[CoversTrait(HasRoleHierarchy::class)]
#[CoversTrait(ManagesPermissions::class)]
#[CoversTrait(HasRoles::class)]
#[CoversTrait(HasPermissions::class)]
#[CoversTrait(HasPolicies::class)]
final class SyncEventsTest extends TestCase
{
    /**
     * `syncRoles` adding two and removing one fires two
     * `IdentityRoleAssigned` and one `IdentityRoleRevoked`.
     *
     * @return void
     */
    public function testSyncRolesDispatchesEventsPerDelta(): void
    {
        Role::create(['id' => (string) Str::uuid(), 'name' => 'a', 'guard_name' => 'web']);
        Role::create(['id' => (string) Str::uuid(), 'name' => 'b', 'guard_name' => 'web']);
        Role::create(['id' => (string) Str::uuid(), 'name' => 'c', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole('a');

        Event::fake([IdentityRoleAssigned::class, IdentityRoleRevoked::class]);

        $user->syncRoles(['b', 'c']);

        Event::assertDispatchedTimes(IdentityRoleAssigned::class, 2);
        Event::assertDispatchedTimes(IdentityRoleRevoked::class, 1);
        Event::assertDispatched(
            IdentityRoleAssigned::class,
            static fn (IdentityRoleAssigned $e): bool => $e->role->name === 'b',
        );
        Event::assertDispatched(
            IdentityRoleAssigned::class,
            static fn (IdentityRoleAssigned $e): bool => $e->role->name === 'c',
        );
        Event::assertDispatched(
            IdentityRoleRevoked::class,
            static fn (IdentityRoleRevoked $e): bool => $e->role->name === 'a',
        );
    }

    /**
     * Re-syncing the same set of roles dispatches no events —
     * `sync()` produces an empty `attached` / `detached` delta.
     *
     * @return void
     */
    public function testSyncRolesIsSilentWhenSetIsUnchanged(): void
    {
        Role::create(['id' => (string) Str::uuid(), 'name' => 'a', 'guard_name' => 'web']);
        Role::create(['id' => (string) Str::uuid(), 'name' => 'b', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->syncRoles(['a', 'b']);

        Event::fake([IdentityRoleAssigned::class, IdentityRoleRevoked::class]);

        $user->syncRoles(['a', 'b']);

        Event::assertNotDispatched(IdentityRoleAssigned::class);
        Event::assertNotDispatched(IdentityRoleRevoked::class);
    }

    /**
     * `syncPermissions` adding two and removing one fires two
     * `IdentityPermissionGranted` and one
     * `IdentityPermissionRevoked`.
     *
     * @return void
     */
    public function testSyncPermissionsDispatchesEventsPerDelta(): void
    {
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'a:do', 'guard_name' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'b:do', 'guard_name' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'c:do', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission('a:do');

        Event::fake([IdentityPermissionGranted::class, IdentityPermissionRevoked::class]);

        $user->syncPermissions(['b:do', 'c:do']);

        Event::assertDispatchedTimes(IdentityPermissionGranted::class, 2);
        Event::assertDispatchedTimes(IdentityPermissionRevoked::class, 1);
        Event::assertDispatched(
            IdentityPermissionGranted::class,
            static fn (IdentityPermissionGranted $e): bool => $e->permission->name === 'b:do',
        );
        Event::assertDispatched(
            IdentityPermissionGranted::class,
            static fn (IdentityPermissionGranted $e): bool => $e->permission->name === 'c:do',
        );
        Event::assertDispatched(
            IdentityPermissionRevoked::class,
            static fn (IdentityPermissionRevoked $e): bool => $e->permission->name === 'a:do',
        );
    }

    /**
     * `syncPolicies` adding two and removing one fires two
     * `IdentityPolicyAttached` and one `IdentityPolicyDetached`.
     *
     * @return void
     */
    public function testSyncPoliciesDispatchesEventsPerDelta(): void
    {
        $a = $this->makeNamedPolicy('a', 'x');
        $b = $this->makeNamedPolicy('b', 'y');
        $c = $this->makeNamedPolicy('c', 'z');

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->attachPolicy($a);

        Event::fake([IdentityPolicyAttached::class, IdentityPolicyDetached::class]);

        $user->syncPolicies([$b, $c]);

        Event::assertDispatchedTimes(IdentityPolicyAttached::class, 2);
        Event::assertDispatchedTimes(IdentityPolicyDetached::class, 1);
        Event::assertDispatched(
            IdentityPolicyAttached::class,
            static fn (IdentityPolicyAttached $e): bool => $e->policy->name === 'b',
        );
        Event::assertDispatched(
            IdentityPolicyAttached::class,
            static fn (IdentityPolicyAttached $e): bool => $e->policy->name === 'c',
        );
        Event::assertDispatched(
            IdentityPolicyDetached::class,
            static fn (IdentityPolicyDetached $e): bool => $e->policy->name === 'a',
        );
    }

    /**
     * `Role::syncPermissions` adding two and removing one fires
     * two `RolePermissionGranted` and one `RolePermissionRevoked`.
     *
     * @return void
     */
    public function testRoleSyncPermissionsDispatchesEventsPerDelta(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'editor',
            'guard_name' => 'web',
        ]);

        Permission::create(['id' => (string) Str::uuid(), 'name' => 'a:do', 'guard_name' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'b:do', 'guard_name' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'c:do', 'guard_name' => 'web']);

        $role->givePermission('a:do');

        Event::fake([RolePermissionGranted::class, RolePermissionRevoked::class]);

        $role->syncPermissions(['b:do', 'c:do']);

        Event::assertDispatchedTimes(RolePermissionGranted::class, 2);
        Event::assertDispatchedTimes(RolePermissionRevoked::class, 1);
        Event::assertDispatched(
            RolePermissionGranted::class,
            static fn (RolePermissionGranted $e): bool => $e->permission->name === 'b:do',
        );
        Event::assertDispatched(
            RolePermissionGranted::class,
            static fn (RolePermissionGranted $e): bool => $e->permission->name === 'c:do',
        );
        Event::assertDispatched(
            RolePermissionRevoked::class,
            static fn (RolePermissionRevoked $e): bool => $e->permission->name === 'a:do',
        );
    }

    /**
     * Re-syncing the same set on a role dispatches no events.
     *
     * @return void
     */
    public function testRoleSyncPermissionsIsSilentWhenSetIsUnchanged(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'editor',
            'guard_name' => 'web',
        ]);

        Permission::create(['id' => (string) Str::uuid(), 'name' => 'a:do', 'guard_name' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'b:do', 'guard_name' => 'web']);

        $role->syncPermissions(['a:do', 'b:do']);

        Event::fake([RolePermissionGranted::class, RolePermissionRevoked::class]);

        $role->syncPermissions(['a:do', 'b:do']);

        Event::assertNotDispatched(RolePermissionGranted::class);
        Event::assertNotDispatched(RolePermissionRevoked::class);
    }

    /**
     * Persist a minimal allow-only policy under the given name and
     * single action — sync-event fixture helper.
     *
     * @param  string  $name
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private function makeNamedPolicy(string $name, string $action): Policy
    {
        return Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => $name,
            'document' => ['statements' => [['effect' => 'allow', 'actions' => [$action]]]],
        ]);
    }
}
