<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\PermissionObserver;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\PermissionService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Performance\Support\CountingSubjectResolver;
use Tests\TestCase;

/**
 * Feature tests for row-level multi-tenant role and permission scoping.
 *
 * Verifies that the `TenantScope` global scope, the subject resolver's tenant,
 * and the tenant ownership helpers on `Role` and `Permission` behave correctly
 * under various tenant contexts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 * @SuppressWarnings("php:S1448")
 */
#[CoversClass(TenantScope::class)]
#[CoversClass(Role::class)]
#[CoversClass(Permission::class)]
#[CoversClass(RoleObserver::class)]
#[CoversClass(PermissionObserver::class)]
#[CoversClass(InvalidTenantException::class)]
#[CoversClass(InvalidTenantColumnsException::class)]
final class TenantScopingTest extends TestCase
{
    /**
     * When no tenant is resolved only platform-wide roles are visible, never
     * every tenant's.
     *
     * @return void
     */
    public function testNullResolverShowsOnlyPlatformRoles(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Role::create(['name' => 'global-role', 'guard' => 'web']);
        Role::create([
            'name'        => 'tenant-role',
            'guard'       => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            // @phpstan-ignore-next-line cast.string
            'tenant_id' => (string) $tenantA->getKey(),
        ]);

        self::assertSame(['global-role'], Role::query()->pluck('name')->all());
    }

    /**
     * When no tenant is resolved only platform-wide permissions are visible,
     * never every tenant's.
     *
     * @return void
     */
    public function testNullResolverShowsOnlyPlatformPermissions(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Permission::create(['name' => 'global-perm', 'guard' => 'web']);
        Permission::create([
            'name'        => 'tenant-perm',
            'guard'       => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            // @phpstan-ignore-next-line cast.string
            'tenant_id' => (string) $tenantA->getKey(),
        ]);

        self::assertSame(['global-perm'], Permission::query()->pluck('name')->all());
    }

    /**
     * An active tenant sees both global roles and its own roles.
     *
     * @return void
     */
    public function testActiveTenantSeesGlobalAndOwnRoles(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);
        $tenantB = StubTenant::create(['id' => 'tenant-b', 'name' => 'Tenant B']);

        Role::create(['name' => 'global-role', 'guard' => 'web']);
        Role::create([
            'name'        => 'role-a',
            'guard'       => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            // @phpstan-ignore-next-line cast.string
            'tenant_id' => (string) $tenantA->getKey(),
        ]);
        Role::create([
            'name'        => 'role-b',
            'guard'       => 'web',
            'tenant_type' => $tenantB->getMorphClass(),
            // @phpstan-ignore-next-line cast.string
            'tenant_id' => (string) $tenantB->getKey(),
        ]);

        $this->bindSubjectInTenant($tenantA);

        $roles = Role::all();

        self::assertCount(2, $roles);
        self::assertTrue($roles->pluck('name')->contains('global-role'));
        self::assertTrue($roles->pluck('name')->contains('role-a'));
        self::assertFalse($roles->pluck('name')->contains('role-b'));
    }

    /**
     * Roles owned by a different tenant must be filtered out.
     *
     * @return void
     */
    public function testDifferentTenantRolesAreInvisible(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);
        $tenantB = StubTenant::create(['id' => 'tenant-b', 'name' => 'Tenant B']);

        Role::create([
            'name'        => 'role-b',
            'guard'       => 'web',
            'tenant_type' => $tenantB->getMorphClass(),
            // @phpstan-ignore-next-line cast.string
            'tenant_id' => (string) $tenantB->getKey(),
        ]);

        $this->bindSubjectInTenant($tenantA);

        self::assertCount(0, Role::all());
    }

    /**
     * Global roles stay visible no matter which tenant is active.
     *
     * @return void
     */
    public function testGlobalRolesAlwaysVisibleRegardlessOfTenant(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Role::create(['name' => 'global-role', 'guard' => 'web']);

        $this->bindSubjectInTenant($tenantA);

        $roles = Role::all();

        self::assertCount(1, $roles);
        self::assertSame('global-role', $roles->first()->name); // @phpstan-ignore property.nonObject
    }

    /**
     * An active tenant sees both global permissions and its own.
     *
     * @return void
     */
    public function testActiveTenantSeesGlobalAndOwnPermissions(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);
        $tenantB = StubTenant::create(['id' => 'tenant-b', 'name' => 'Tenant B']);

        Permission::create(['name' => 'global-perm', 'guard' => 'web']);
        Permission::create([
            'name'        => 'perm-a',
            'guard'       => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            // @phpstan-ignore-next-line cast.string
            'tenant_id' => (string) $tenantA->getKey(),
        ]);
        Permission::create([
            'name'        => 'perm-b',
            'guard'       => 'web',
            'tenant_type' => $tenantB->getMorphClass(),
            // @phpstan-ignore-next-line cast.string
            'tenant_id' => (string) $tenantB->getKey(),
        ]);

        $this->bindSubjectInTenant($tenantA);

        $perms = Permission::all();

        self::assertCount(2, $perms);
        self::assertTrue($perms->pluck('name')->contains('global-perm'));
        self::assertTrue($perms->pluck('name')->contains('perm-a'));
        self::assertFalse($perms->pluck('name')->contains('perm-b'));
    }

    /**
     * Name-based role resolution honours the active tenant scope.
     *
     * @return void
     */
    public function testResolveByNameReturnsTenantScopedRole(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        // A platform role and a tenant-owned role may share a name and guard:
        // the tenant's row wins for that tenant.
        Role::create(['name' => 'editor', 'guard' => 'web']);
        Role::create([
            'name'        => 'editor',
            'guard'       => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            // @phpstan-ignore-next-line cast.string
            'tenant_id' => (string) $tenantA->getKey(),
        ]);

        $this->bindSubjectInTenant($tenantA);

        $resolved = app(RoleService::class)->find('editor', 'web');

        self::assertNotNull(Reference::tenantOf($resolved));
        self::assertSame((string) $tenantA->getKey(), $resolved->tenant_id); // @phpstan-ignore cast.string
    }

    /**
     * Name-based permission resolution honours the tenant scope.
     *
     * @return void
     */
    public function testResolveByNameReturnsTenantScopedPermission(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Permission::create(['name' => 'posts:edit', 'guard' => 'web']);
        Permission::create([
            'name'        => 'posts:edit',
            'guard'       => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            // @phpstan-ignore-next-line cast.string
            'tenant_id' => (string) $tenantA->getKey(),
        ]);

        $this->bindSubjectInTenant($tenantA);

        $resolved = app(PermissionService::class)->find('posts:edit', 'web');

        self::assertNotNull(Reference::tenantOf($resolved));
        self::assertSame((string) $tenantA->getKey(), $resolved->tenant_id); // @phpstan-ignore cast.string
    }

    /**
     * Creating a role with a tenant stores both tenant columns.
     *
     * @return void
     */
    public function testCreatingRoleWithTenantPersistsCorrectly(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $role = Role::create([
            'name'        => 'tenant-editor',
            'guard'       => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        self::assertSame($tenantA->getMorphClass(), $role->tenant_type);
        self::assertSame((string) $tenantA->getKey(), $role->tenant_id); // @phpstan-ignore cast.string

        $fresh = Role::withoutGlobalScopes()->find($role->getKey());

        self::assertNotNull($fresh);
        self::assertSame($tenantA->getMorphClass(), $fresh->tenant_type); // @phpstan-ignore property.notFound
        self::assertSame((string) $tenantA->getKey(), $fresh->tenant_id); // @phpstan-ignore cast.string, property.notFound
    }

    /**
     * Creating a permission with a tenant stores both tenant columns.
     *
     * @return void
     */
    public function testCreatingPermissionWithTenantPersistsCorrectly(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $permission = Permission::create([
            'name'        => 'tenant-perm',
            'guard'       => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        self::assertSame($tenantA->getMorphClass(), $permission->tenant_type);
        self::assertSame((string) $tenantA->getKey(), $permission->tenant_id); // @phpstan-ignore cast.string
    }

    /**
     * An identity assigned a tenant role receives the expected permissions.
     *
     * @return void
     */
    public function testIdentityWithTenantRoleGetsCorrectPermissions(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $this->bindSubjectInTenant($tenantA);

        $role = Role::create([
            'name'        => 'editor',
            'guard'       => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        $permission = Permission::create([
            'name'        => 'posts:edit',
            'guard'       => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        $role->givePermission($permission);

        $identity = StubIdentity::create(['id' => 'user-1', 'name' => 'Alice']);
        $identity->assignRole($role);

        self::assertTrue($identity->hasRole('editor'));
        self::assertTrue($identity->hasPermission('posts:edit'));
    }

    /**
     * The polymorphic tenant relation resolves on a role.
     *
     * @return void
     */
    public function testTenantRelationResolvesOnRole(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $role = Role::create([
            'name'        => 'editor',
            'guard'       => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        $resolved = $role->tenant;

        self::assertNotNull($resolved);
        self::assertSame('tenant-a', (string) $resolved->getKey()); // @phpstan-ignore cast.string
    }

    /**
     * The tenant relation returns null for a global role.
     *
     * @return void
     */
    public function testTenantRelationReturnsNullForGlobalRole(): void
    {
        $role = Role::create(['name' => 'global', 'guard' => 'web']);

        self::assertNull($role->tenant);
    }

    /**
     * The polymorphic tenant relation resolves on a permission.
     *
     * @return void
     */
    public function testTenantRelationResolvesOnPermission(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $permission = Permission::create([
            'name'        => 'posts:edit',
            'guard'       => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        $resolved = $permission->tenant;

        self::assertNotNull($resolved);
        self::assertSame('tenant-a', (string) $resolved->getKey()); // @phpstan-ignore cast.string
    }

    /**
     * The subject resolver is consulted once per request or job for the tenant
     * — a spy resolver wrapping a concrete tenant records one `resolve()` call
     * regardless of how many Eloquent queries the scope filters, on either
     * model.
     *
     * @return void
     */
    public function testSubjectsTenantIsMemoisedAcrossQueries(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Role::create([
            'name'        => 'role-a',
            'guard'       => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            // @phpstan-ignore-next-line cast.string
            'tenant_id' => (string) $tenantA->getKey(),
        ]);
        Role::create(['name' => 'global-role', 'guard' => 'web']);
        Permission::create([
            'name'        => 'perm-a',
            'guard'       => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            // @phpstan-ignore-next-line cast.string
            'tenant_id' => (string) $tenantA->getKey(),
        ]);

        $spy = new CountingSubjectResolver($tenantA);

        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        // Binding the spy drops the tenant resolved by the queries above, so
        // the spy is asked on the next query.
        $app->instance(SubjectResolver::class, $spy);

        // Issue multiple queries against both scoped models — each one invokes
        // `TenantScope::apply`. Without memoisation the spy would record one
        // call per query.
        Role::all();
        Role::all();
        Role::query()->where('name', 'role-a')->get();
        Permission::all();
        Permission::query()->where('name', 'perm-a')->get();

        // One call for the request: the resolved tenant is held by the
        // container, not by each model's scope instance.
        self::assertSame(1, $spy->calls);
    }

    /**
     * A resolver that returns an object which is neither an Eloquent `Model`
     * nor an `AuthorizableTenant` implementer is refused at the scope boundary
     * with `InvalidTenantException` — no silent `spl_object_hash` fallback.
     *
     * @return void
     */
    public function testNonModelNonIdentifierTenantIsRefused(): void
    {
        $opaque = new \stdClass;

        $this->bindSubjectInTenant($opaque);

        $this->expectException(InvalidTenantException::class);
        $this->expectExceptionMessageMatches('/stdClass/');

        Role::all();
    }

    /**
     * A custom tenant implementing `AuthorizableTenant` is accepted by the
     * scope and matches rows written with the contract's `getMorphClass()` /
     * `getKey()` values.
     *
     * @return void
     */
    public function testAuthorizableTenantImplementerIsAcceptedByScope(): void
    {
        $customTenant = new class implements AuthorizableTenant {
            /**
             * @return string
             */
            #[\Override]
            public function getKey(): string
            {
                return 'custom-tenant-42';
            }

            /**
             * @return string
             */
            #[\Override]
            public function getMorphClass(): string
            {
                return 'App\Tenancy\CustomTenant';
            }
        };

        Role::create([
            'name'        => 'custom-role',
            'guard'       => 'web',
            'tenant_type' => $customTenant->getMorphClass(),
            'tenant_id'   => (string) $customTenant->getKey(), // @phpstan-ignore cast.useless
        ]);
        Role::create(['name' => 'global-role', 'guard' => 'web']);

        $this->bindSubjectInTenant($customTenant);

        $roles = Role::all();

        self::assertCount(2, $roles);
        self::assertTrue($roles->pluck('name')->contains('custom-role'));
        self::assertTrue($roles->pluck('name')->contains('global-role'));
    }

    /**
     * Persisting a Role with only `tenant_type` (tenant_id null) raises
     * `InvalidTenantColumnsException` before the row hits the database.
     *
     * @return void
     */
    public function testRoleWithHalfSetTenantColumnsRaisesException(): void
    {
        $this->expectException(InvalidTenantColumnsException::class);
        $this->expectExceptionMessageMatches('/tenant_id/');

        Role::create([
            'name'        => 'broken-role',
            'guard'       => 'web',
            'tenant_type' => 'App\Tenant',
            'tenant_id'   => null,
        ]);
    }

    /**
     * The inverse case — `tenant_id` set with `tenant_type` null — is refused
     * with the same exception.
     *
     * @return void
     */
    public function testRoleWithTenantIdButNoTenantTypeRaisesException(): void
    {
        $this->expectException(InvalidTenantColumnsException::class);
        $this->expectExceptionMessageMatches('/tenant_type/');

        Role::create([
            'name'        => 'broken-role',
            'guard'       => 'web',
            'tenant_type' => null,
            'tenant_id'   => 'tenant-x',
        ]);
    }

    /**
     * Permissions carry the same tenant-column invariant.
     *
     * @return void
     */
    public function testPermissionWithHalfSetTenantColumnsRaisesException(): void
    {
        $this->expectException(InvalidTenantColumnsException::class);
        $this->expectExceptionMessageMatches('/tenant_id/');

        Permission::create([
            'name'        => 'broken-perm',
            'guard'       => 'web',
            'tenant_type' => 'App\Tenant',
            'tenant_id'   => null,
        ]);
    }

    /**
     * Bind a subject resolver whose subject carries the given tenant.
     *
     * @param  object|null  $tenant
     * @return void
     */
    private function bindSubjectInTenant(?object $tenant): void
    {
        // @phpstan-ignore-next-line method.nonObject
        $this->app->singleton(SubjectResolver::class, static fn (): SubjectResolver => new StubSubjectResolver(new \stdClass, $tenant));
    }
}
