<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
use SineMacula\Laravel\Authorization\Concerns\HasRoleHierarchy;
use SineMacula\Laravel\Authorization\Concerns\ManagesPermissions;
use SineMacula\Laravel\Authorization\Events\Role\PermissionGranted as RolePermissionGranted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionRevoked as RolePermissionRevoked;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use SineMacula\Laravel\Authorization\Resolvers\NullTenantResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use Tests\TestCase;

/**
 * Feature coverage for the role permission-management API.
 *
 * The surface mirrors the identity-side `HasPermissions` trait — string or
 * model input, guard-agnostic lookup, idempotent attach, typed error on an
 * unknown permission — so consumers can reach for the same verbs on both sides
 * of the RBAC edge.
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
final class RolePermissionApiTest extends TestCase
{
    /** Canonical role name used across scenarios. */
    private const string ROLE_NAME = 'editor';

    /** Canonical permission name used across scenarios. */
    private const string PERMISSION_NAME = 'posts:create';

    /**
     * givePermission attaches a permission by string name and dispatches the
     * RolePermissionGranted event.
     *
     * @return void
     */
    public function testGivePermissionAttachesByStringAndDispatchesEvent(): void
    {
        Event::fake([RolePermissionGranted::class]);

        $role       = $this->makeRole();
        $permission = $this->makePermission();

        $role->givePermission(self::PERMISSION_NAME);

        self::assertTrue($role->fresh()?->hasPermission(self::PERMISSION_NAME));
        Event::assertDispatched(
            RolePermissionGranted::class,
            static fn (RolePermissionGranted $event): bool => $event->role->is($role)
                && $event->permission->is($permission),
        );
    }

    /**
     * givePermission accepts a Permission model instance and bypasses the
     * string-lookup path.
     *
     * @return void
     */
    public function testGivePermissionAcceptsModelInstance(): void
    {
        $role       = $this->makeRole();
        $permission = $this->makePermission();

        $role->givePermission($permission);

        self::assertTrue($role->fresh()?->hasPermission($permission));
    }

    /**
     * Re-attaching a permission is idempotent — no duplicate pivot row, no
     * second event (sync-without-detaching semantics).
     *
     * @return void
     */
    public function testGivePermissionIsIdempotent(): void
    {
        $role = $this->makeRole();
        $this->makePermission();

        $role->givePermission(self::PERMISSION_NAME);
        $role->givePermission(self::PERMISSION_NAME);

        self::assertCount(1, $role->fresh()?->permissions ?? []); // @phpstan-ignore nullsafe.neverNull
    }

    /**
     * revokePermission detaches by string name and dispatches the
     * RolePermissionRevoked event.
     *
     * @return void
     */
    public function testRevokePermissionDetachesAndDispatchesEvent(): void
    {
        Event::fake([RolePermissionRevoked::class]);

        $role       = $this->makeRole();
        $permission = $this->makePermission();

        $role->givePermission(self::PERMISSION_NAME);
        $role->revokePermission(self::PERMISSION_NAME);

        self::assertFalse($role->fresh()?->hasPermission(self::PERMISSION_NAME));
        Event::assertDispatched(
            RolePermissionRevoked::class,
            static fn (RolePermissionRevoked $event): bool => $event->role->is($role)
                && $event->permission->is($permission),
        );
    }

    /**
     * syncPermissions replaces the attached set wholesale.
     *
     * @return void
     */
    public function testSyncPermissionsReplacesSet(): void
    {
        $role = $this->makeRole();
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'a:do', 'guard_name' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'b:do', 'guard_name' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'c:do', 'guard_name' => 'web']);

        $role->syncPermissions(['a:do', 'b:do']);
        self::assertSame(['a:do', 'b:do'], $this->sortedNames($role));

        $role->syncPermissions(['c:do']);
        self::assertSame(['c:do'], $this->sortedNames($role));
    }

    /**
     * getPermissions returns the unique set of attached permission names.
     *
     * @return void
     */
    public function testGetPermissionsReturnsNameList(): void
    {
        $role = $this->makeRole();
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'a:do', 'guard_name' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'b:do', 'guard_name' => 'web']);

        $role->syncPermissions(['a:do', 'b:do']);

        self::assertSame(['a:do', 'b:do'], $this->sortedNames($role));
    }

    /**
     * An unknown permission name raises UnknownPermissionException.
     *
     * @return void
     */
    public function testUnknownPermissionNameThrows(): void
    {
        $role = $this->makeRole();

        $this->expectException(UnknownPermissionException::class);

        $role->givePermission('does:not-exist');
    }

    /**
     * A guard-agnostic permission attaches cleanly to a guard-specific role.
     *
     * @return void
     */
    public function testGuardAgnosticPermissionAttachesToGuardSpecificRole(): void
    {
        $role = $this->makeRole();
        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'platform:ping',
            'guard_name' => null,
        ]);

        $role->givePermission('platform:ping');

        self::assertTrue($role->fresh()?->hasPermission('platform:ping'));
    }

    /**
     * Spatie aliases forward to the canonical helpers.
     *
     * @return void
     */
    public function testSpatieAliasesDelegate(): void
    {
        $role = $this->makeRole();
        $this->makePermission();

        $role->givePermissionTo(self::PERMISSION_NAME);
        self::assertTrue($role->hasPermissionTo(self::PERMISSION_NAME));
        self::assertSame([self::PERMISSION_NAME], $role->getPermissionNames());

        $role->revokePermissionTo(self::PERMISSION_NAME);
        self::assertFalse($role->fresh()?->hasPermissionTo(self::PERMISSION_NAME));
    }

    /**
     * Build a web-guarded role with the canonical name.
     *
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private function makeRole(): Role
    {
        return Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => self::ROLE_NAME,
            'guard_name' => 'web',
        ]);
    }

    /**
     * Build a web-guarded permission with the canonical name.
     *
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private function makePermission(): Permission
    {
        return Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => self::PERMISSION_NAME,
            'guard_name' => 'web',
        ]);
    }

    /**
     * Return the role's attached permission names sorted ascending.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return array<int, string>
     */
    private function sortedNames(Role $role): array
    {
        $names = $role->fresh()?->getPermissions() ?? [];
        \sort($names);

        return \array_values($names); // @phpstan-ignore arrayValues.list
    }
}
