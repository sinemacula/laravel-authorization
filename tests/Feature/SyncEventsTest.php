<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\HasPermissions;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Concerns\HasRoleHierarchy;
use SineMacula\Laravel\Authorization\Concerns\HasRoles;
use SineMacula\Laravel\Authorization\Concerns\ManagesPermissions;
use SineMacula\Laravel\Authorization\Events\Grantee\PermissionGranted as GranteePermissionGranted;
use SineMacula\Laravel\Authorization\Events\Grantee\PermissionRevoked as GranteePermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Grantee\PolicyAttached as GranteePolicyAttached;
use SineMacula\Laravel\Authorization\Events\Grantee\PolicyDetached as GranteePolicyDetached;
use SineMacula\Laravel\Authorization\Events\Grantee\RoleAssigned as GranteeRoleAssigned;
use SineMacula\Laravel\Authorization\Events\Grantee\RoleRevoked as GranteeRoleRevoked;
use SineMacula\Laravel\Authorization\Events\Role\PermissionGranted as RolePermissionGranted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionRevoked as RolePermissionRevoked;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use Tests\Feature\Stubs\StubGrantee;
use Tests\TestCase;

/**
 * Feature coverage for the per-row events that `sync*` methods dispatch.
 *
 * Each `sync*` method on the trait triad and on `Role` consults the delta
 * returned by Eloquent's `sync()` and dispatches the matching single-item event
 * for every attached and detached pivot row, so audit consumers receive the
 * same per-row signal they would for the corresponding `assignRole` /
 * `givePermission` / `attachPolicy` / role-side `givePermission` calls.
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
#[CoversClass(GranteeRoleAssigned::class)]
#[CoversClass(GranteeRoleRevoked::class)]
#[CoversClass(GranteePermissionGranted::class)]
#[CoversClass(GranteePermissionRevoked::class)]
#[CoversClass(GranteePolicyAttached::class)]
#[CoversClass(GranteePolicyDetached::class)]
#[CoversClass(RolePermissionGranted::class)]
#[CoversClass(RolePermissionRevoked::class)]
#[CoversClass(TenantScope::class)]
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
     * `syncRoles` adding two and removing one fires two `GranteeRoleAssigned`
     * and one `GranteeRoleRevoked`.
     *
     * @return void
     */
    public function testSyncRolesDispatchesEventsPerDelta(): void
    {
        Role::create(['id' => (string) Str::uuid(), 'name' => 'a', 'guard' => 'web']);
        Role::create(['id' => (string) Str::uuid(), 'name' => 'b', 'guard' => 'web']);
        Role::create(['id' => (string) Str::uuid(), 'name' => 'c', 'guard' => 'web']);

        $user = StubGrantee::create(['id' => (string) Str::uuid()]);
        $user->assignRole('a');

        Event::fake([GranteeRoleAssigned::class, GranteeRoleRevoked::class]);

        $user->syncRoles(['b', 'c']);

        Event::assertDispatchedTimes(GranteeRoleAssigned::class, 2);
        Event::assertDispatchedTimes(GranteeRoleRevoked::class, 1);
        Event::assertDispatched(
            GranteeRoleAssigned::class,
            static fn (GranteeRoleAssigned $e): bool => $e->name === 'b',
        );
        Event::assertDispatched(
            GranteeRoleAssigned::class,
            static fn (GranteeRoleAssigned $e): bool => $e->name === 'c',
        );
        Event::assertDispatched(
            GranteeRoleRevoked::class,
            static fn (GranteeRoleRevoked $e): bool => $e->name === 'a',
        );
    }

    /**
     * Re-syncing the same set of roles dispatches no events — `sync()` produces
     * an empty `attached` / `detached` delta.
     *
     * @return void
     */
    public function testSyncRolesIsSilentWhenSetIsUnchanged(): void
    {
        Role::create(['id' => (string) Str::uuid(), 'name' => 'a', 'guard' => 'web']);
        Role::create(['id' => (string) Str::uuid(), 'name' => 'b', 'guard' => 'web']);

        $user = StubGrantee::create(['id' => (string) Str::uuid()]);
        $user->syncRoles(['a', 'b']);

        Event::fake([GranteeRoleAssigned::class, GranteeRoleRevoked::class]);

        $user->syncRoles(['a', 'b']);

        Event::assertNotDispatched(GranteeRoleAssigned::class);
        Event::assertNotDispatched(GranteeRoleRevoked::class);
    }

    /**
     * `syncPermissions` adding two and removing one fires two
     * `GranteePermissionGranted` and one `GranteePermissionRevoked`.
     *
     * @return void
     */
    public function testSyncPermissionsDispatchesEventsPerDelta(): void
    {
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'a:do', 'guard' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'b:do', 'guard' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'c:do', 'guard' => 'web']);

        $user = StubGrantee::create(['id' => (string) Str::uuid()]);
        $user->givePermission('a:do');

        Event::fake([GranteePermissionGranted::class, GranteePermissionRevoked::class]);

        $user->syncPermissions(['b:do', 'c:do']);

        Event::assertDispatchedTimes(GranteePermissionGranted::class, 2);
        Event::assertDispatchedTimes(GranteePermissionRevoked::class, 1);
        Event::assertDispatched(
            GranteePermissionGranted::class,
            static fn (GranteePermissionGranted $e): bool => $e->name === 'b:do',
        );
        Event::assertDispatched(
            GranteePermissionGranted::class,
            static fn (GranteePermissionGranted $e): bool => $e->name === 'c:do',
        );
        Event::assertDispatched(
            GranteePermissionRevoked::class,
            static fn (GranteePermissionRevoked $e): bool => $e->name === 'a:do',
        );
    }

    /**
     * `syncPolicies` adding two and removing one fires two
     * `GranteePolicyAttached` and one `GranteePolicyDetached`.
     *
     * @return void
     */
    public function testSyncPoliciesDispatchesEventsPerDelta(): void
    {
        $a = $this->makeNamedPolicy('a', 'x');
        $b = $this->makeNamedPolicy('b', 'y');
        $c = $this->makeNamedPolicy('c', 'z');

        $user = StubGrantee::create(['id' => (string) Str::uuid()]);
        $user->attachPolicy($a);

        Event::fake([GranteePolicyAttached::class, GranteePolicyDetached::class]);

        $user->syncPolicies([$b, $c]);

        Event::assertDispatchedTimes(GranteePolicyAttached::class, 2);
        Event::assertDispatchedTimes(GranteePolicyDetached::class, 1);
        Event::assertDispatched(
            GranteePolicyAttached::class,
            static fn (GranteePolicyAttached $e): bool => $e->name === 'b',
        );
        Event::assertDispatched(
            GranteePolicyAttached::class,
            static fn (GranteePolicyAttached $e): bool => $e->name === 'c',
        );
        Event::assertDispatched(
            GranteePolicyDetached::class,
            static fn (GranteePolicyDetached $e): bool => $e->name === 'a',
        );
    }

    /**
     * `Role::syncPermissions` adding two and removing one fires two
     * `RolePermissionGranted` and one `RolePermissionRevoked`.
     *
     * @return void
     */
    public function testRoleSyncPermissionsDispatchesEventsPerDelta(): void
    {
        $role = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'editor',
            'guard' => 'web',
        ]);

        Permission::create(['id' => (string) Str::uuid(), 'name' => 'a:do', 'guard' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'b:do', 'guard' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'c:do', 'guard' => 'web']);

        $role->givePermission('a:do');

        Event::fake([RolePermissionGranted::class, RolePermissionRevoked::class]);

        $role->syncPermissions(['b:do', 'c:do']);

        Event::assertDispatchedTimes(RolePermissionGranted::class, 2);
        Event::assertDispatchedTimes(RolePermissionRevoked::class, 1);
        Event::assertDispatched(
            RolePermissionGranted::class,
            static fn (RolePermissionGranted $e): bool => $e->permissionName === 'b:do',
        );
        Event::assertDispatched(
            RolePermissionGranted::class,
            static fn (RolePermissionGranted $e): bool => $e->permissionName === 'c:do',
        );
        Event::assertDispatched(
            RolePermissionRevoked::class,
            static fn (RolePermissionRevoked $e): bool => $e->permissionName === 'a:do',
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
            'id'    => (string) Str::uuid(),
            'name'  => 'editor',
            'guard' => 'web',
        ]);

        Permission::create(['id' => (string) Str::uuid(), 'name' => 'a:do', 'guard' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'b:do', 'guard' => 'web']);

        $role->syncPermissions(['a:do', 'b:do']);

        Event::fake([RolePermissionGranted::class, RolePermissionRevoked::class]);

        $role->syncPermissions(['a:do', 'b:do']);

        Event::assertNotDispatched(RolePermissionGranted::class);
        Event::assertNotDispatched(RolePermissionRevoked::class);
    }

    /**
     * Persist a minimal allow-only policy under the given name and single
     * action — sync-event fixture helper.
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
