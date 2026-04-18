<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\PermissionObserver;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for row-level multi-tenant role and permission scoping.
 *
 * Verifies that the `TenantScope` global scope, `TenantResolver` contract, and
 * the tenant ownership helpers on `Role` and `Permission` behave correctly
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
#[CoversClass(ConfigValidator::class)]
#[CoversClass(InvalidAuthorizationConfigException::class)]
class TenantScopingTest extends TestCase
{
    /**
     * When no tenant resolver is bound every role remains visible.
     *
     * @return void
     */
    public function testNullResolverShowsAllRoles(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Role::create(['name' => 'global-role', 'guard_name' => 'web']);
        Role::create([
            'name'        => 'tenant-role',
            'guard_name'  => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            // @phpstan-ignore-next-line cast.string
            'tenant_id' => (string) $tenantA->getKey(),
        ]);

        static::assertCount(2, Role::all());
    }

    /**
     * When no tenant resolver is bound every permission remains visible.
     *
     * @return void
     */
    public function testNullResolverShowsAllPermissions(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Permission::create(['name' => 'global-perm', 'guard_name' => 'web']);
        Permission::create(['name' => 'tenant-perm', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        static::assertCount(2, Permission::all());
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

        Role::create(['name' => 'global-role', 'guard_name' => 'web']);
        Role::create(['name' => 'role-a', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);
        Role::create(['name' => 'role-b', 'guard_name' => 'web', 'tenant_type' => $tenantB->getMorphClass(), 'tenant_id' => (string) $tenantB->getKey(), // @phpstan-ignore cast.string
        ]);

        $this->bindTenantResolver($tenantA);

        $roles = Role::all();

        static::assertCount(2, $roles);
        static::assertTrue($roles->pluck('name')->contains('global-role'));
        static::assertTrue($roles->pluck('name')->contains('role-a'));
        static::assertFalse($roles->pluck('name')->contains('role-b'));
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

        Role::create(['name' => 'role-b', 'guard_name' => 'web', 'tenant_type' => $tenantB->getMorphClass(), 'tenant_id' => (string) $tenantB->getKey(), // @phpstan-ignore cast.string
        ]);

        $this->bindTenantResolver($tenantA);

        static::assertCount(0, Role::all());
    }

    /**
     * Global roles stay visible no matter which tenant is active.
     *
     * @return void
     */
    public function testGlobalRolesAlwaysVisibleRegardlessOfTenant(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Role::create(['name' => 'global-role', 'guard_name' => 'web']);

        $this->bindTenantResolver($tenantA);

        $roles = Role::all();

        static::assertCount(1, $roles);
        static::assertSame('global-role', $roles->first()->name); // @phpstan-ignore property.nonObject
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

        Permission::create(['name' => 'global-perm', 'guard_name' => 'web']);
        Permission::create(['name' => 'perm-a', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);
        Permission::create(['name' => 'perm-b', 'guard_name' => 'web', 'tenant_type' => $tenantB->getMorphClass(), 'tenant_id' => (string) $tenantB->getKey(), // @phpstan-ignore cast.string
        ]);

        $this->bindTenantResolver($tenantA);

        $perms = Permission::all();

        static::assertCount(2, $perms);
        static::assertTrue($perms->pluck('name')->contains('global-perm'));
        static::assertTrue($perms->pluck('name')->contains('perm-a'));
        static::assertFalse($perms->pluck('name')->contains('perm-b'));
    }

    /**
     * Name-based role resolution honours the active tenant scope.
     *
     * @return void
     */
    public function testResolveByNameReturnsTenantScopedRole(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        // Create a global role and a tenant-owned role with the
        // same name but different guard to avoid the unique constraint.
        Role::create(['name' => 'editor', 'guard_name' => null]);
        Role::create(['name' => 'editor', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        $this->bindTenantResolver($tenantA);

        $resolved = Role::resolveByName('editor', 'web');

        static::assertTrue($resolved->isTenantOwned());
        static::assertSame((string) $tenantA->getKey(), $resolved->tenant_id); // @phpstan-ignore cast.string
    }

    /**
     * Name-based permission resolution honours the tenant scope.
     *
     * @return void
     */
    public function testResolveByNameReturnsTenantScopedPermission(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Permission::create(['name' => 'posts:edit', 'guard_name' => null]);
        Permission::create(['name' => 'posts:edit', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        $this->bindTenantResolver($tenantA);

        $resolved = Permission::resolveByName('posts:edit', 'web');

        static::assertTrue($resolved->isTenantOwned());
        static::assertSame((string) $tenantA->getKey(), $resolved->tenant_id); // @phpstan-ignore cast.string
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
            'guard_name'  => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        static::assertSame($tenantA->getMorphClass(), $role->tenant_type);
        static::assertSame((string) $tenantA->getKey(), $role->tenant_id); // @phpstan-ignore cast.string

        $fresh = Role::withoutGlobalScopes()->find($role->getKey());

        static::assertNotNull($fresh);
        static::assertSame($tenantA->getMorphClass(), $fresh->tenant_type); // @phpstan-ignore property.notFound
        static::assertSame((string) $tenantA->getKey(), $fresh->tenant_id); // @phpstan-ignore cast.string, property.notFound
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
            'guard_name'  => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        static::assertSame($tenantA->getMorphClass(), $permission->tenant_type);
        static::assertSame((string) $tenantA->getKey(), $permission->tenant_id); // @phpstan-ignore cast.string
    }

    /**
     * `isGlobal` returns true for a role with no tenant owner.
     *
     * @return void
     */
    public function testIsGlobalReturnsTrueForGlobalRole(): void
    {
        $role = Role::create(['name' => 'global', 'guard_name' => 'web']);

        static::assertTrue($role->isGlobal());
        static::assertFalse($role->isTenantOwned());
    }

    /**
     * `isTenantOwned` returns true for a tenant-owned role.
     *
     * @return void
     */
    public function testIsTenantOwnedReturnsTrueForTenantRole(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $role = Role::create([
            'name'        => 'editor',
            'guard_name'  => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        static::assertTrue($role->isTenantOwned());
        static::assertFalse($role->isGlobal());
    }

    /**
     * `isGlobal` returns true for a permission with no tenant owner.
     *
     * @return void
     */
    public function testIsGlobalReturnsTrueForGlobalPermission(): void
    {
        $permission = Permission::create(['name' => 'global-perm', 'guard_name' => 'web']);

        static::assertTrue($permission->isGlobal());
        static::assertFalse($permission->isTenantOwned());
    }

    /**
     * `isTenantOwned` returns true for a tenant-owned permission.
     *
     * @return void
     */
    public function testIsTenantOwnedReturnsTrueForTenantPermission(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $permission = Permission::create([
            'name'        => 'posts:edit',
            'guard_name'  => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        static::assertTrue($permission->isTenantOwned());
        static::assertFalse($permission->isGlobal());
    }

    /**
     * `forTenant` scope filters roles to the given tenant.
     *
     * @return void
     */
    public function testScopeForTenantFiltersRolesByTenant(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);
        $tenantB = StubTenant::create(['id' => 'tenant-b', 'name' => 'Tenant B']);

        Role::create(['name' => 'global', 'guard_name' => 'web']);
        Role::create(['name' => 'role-a', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);
        Role::create(['name' => 'role-b', 'guard_name' => 'web', 'tenant_type' => $tenantB->getMorphClass(), 'tenant_id' => (string) $tenantB->getKey(), // @phpstan-ignore cast.string
        ]);

        $roles = Role::forTenant($tenantA)->get();

        static::assertCount(1, $roles);
        static::assertSame('role-a', $roles->first()->name); // @phpstan-ignore property.nonObject
    }

    /**
     * `globalOnly` scope returns only tenant-less roles.
     *
     * @return void
     */
    public function testScopeGlobalOnlyFiltersRoles(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Role::create(['name' => 'global', 'guard_name' => 'web']);
        Role::create(['name' => 'role-a', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        $roles = Role::globalOnly()->get();

        static::assertCount(1, $roles);
        static::assertSame('global', $roles->first()->name); // @phpstan-ignore property.nonObject
    }

    /**
     * `forTenant` scope filters permissions to the given tenant.
     *
     * @return void
     */
    public function testScopeForTenantFiltersPermissionsByTenant(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);
        $tenantB = StubTenant::create(['id' => 'tenant-b', 'name' => 'Tenant B']);

        Permission::create(['name' => 'global-perm', 'guard_name' => 'web']);
        Permission::create(['name' => 'perm-a', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);
        Permission::create(['name' => 'perm-b', 'guard_name' => 'web', 'tenant_type' => $tenantB->getMorphClass(), 'tenant_id' => (string) $tenantB->getKey(), // @phpstan-ignore cast.string
        ]);

        $perms = Permission::forTenant($tenantA)->get();

        static::assertCount(1, $perms);
        static::assertSame('perm-a', $perms->first()->name); // @phpstan-ignore property.nonObject
    }

    /**
     * `globalOnly` scope returns only tenant-less permissions.
     *
     * @return void
     */
    public function testScopeGlobalOnlyFiltersPermissions(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Permission::create(['name' => 'global-perm', 'guard_name' => 'web']);
        Permission::create(['name' => 'perm-a', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        $perms = Permission::globalOnly()->get();

        static::assertCount(1, $perms);
        static::assertSame('global-perm', $perms->first()->name); // @phpstan-ignore property.nonObject
    }

    /**
     * An identity assigned a tenant role receives the expected permissions.
     *
     * @return void
     */
    public function testIdentityWithTenantRoleGetsCorrectPermissions(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $role = Role::create([
            'name'        => 'editor',
            'guard_name'  => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        $permission = Permission::create([
            'name'        => 'posts:edit',
            'guard_name'  => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        $role->givePermission($permission);

        $identity = StubIdentity::create(['id' => 'user-1', 'name' => 'Alice']);
        $identity->assignRole($role);

        $this->bindTenantResolver($tenantA);

        static::assertTrue($identity->hasRole('editor'));
        static::assertTrue($identity->hasPermission('posts:edit'));
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
            'guard_name'  => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        $resolved = $role->tenant;

        static::assertNotNull($resolved);
        static::assertSame('tenant-a', (string) $resolved->getKey()); // @phpstan-ignore cast.string
    }

    /**
     * The tenant relation returns null for a global role.
     *
     * @return void
     */
    public function testTenantRelationReturnsNullForGlobalRole(): void
    {
        $role = Role::create(['name' => 'global', 'guard_name' => 'web']);

        static::assertNull($role->tenant);
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
            'guard_name'  => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        $resolved = $permission->tenant;

        static::assertNotNull($resolved);
        static::assertSame('tenant-a', (string) $resolved->getKey()); // @phpstan-ignore cast.string
    }

    /**
     * An invalid tenant-resolver config raises a validation exception.
     *
     * @return void
     */
    public function testInvalidTenantResolverConfigThrows(): void
    {
        $this->app['config']->set('authorization.tenant_resolver', 'NonExistent\Class'); // @phpstan-ignore offsetAccess.notFound, method.nonObject

        $this->expectException(\SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessageMatches('/tenant_resolver/');

        /** @var array<string, mixed> $config */
        $config = $this->app['config']->get('authorization', []); // @phpstan-ignore offsetAccess.notFound, method.nonObject

        \SineMacula\Laravel\Authorization\Config\ConfigValidator::validate($config, $this->app);
    }

    /**
     * A null tenant-resolver config passes validation.
     *
     * @return void
     */
    public function testNullTenantResolverConfigPassesValidation(): void
    {
        $this->app['config']->set('authorization.tenant_resolver', null); // @phpstan-ignore offsetAccess.notFound, method.nonObject

        /** @var array<string, mixed> $config */
        $config = $this->app['config']->get('authorization', []); // @phpstan-ignore offsetAccess.notFound, method.nonObject

        \SineMacula\Laravel\Authorization\Config\ConfigValidator::validate($config, $this->app);

        static::assertTrue(true);
    }

    /**
     * The `TenantResolver` is consulted at most once per scope instance per
     * container lifetime — a spy resolver wrapping a concrete tenant records
     * one `resolve()` invocation regardless of how many Eloquent queries the
     * scope filters.
     *
     * @return void
     */
    public function testTenantResolverIsMemoisedAcrossQueries(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Role::create(['name' => 'role-a', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);
        Role::create(['name' => 'global-role', 'guard_name' => 'web']);
        Permission::create(['name' => 'perm-a', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey(), // @phpstan-ignore cast.string
        ]);

        /**
         * Counting tenant resolver used to verify memoisation.
         */
        $spy = new class ($tenantA) implements TenantResolver {
            /** @var int Number of times `resolve` was invoked. */
            public int $calls = 0;

            /**
             * Create a new spy wrapping a fixed tenant.
             *
             * @param  object|null  $tenant
             * @return void
             */
            public function __construct(

                /** The tenant returned by every resolution call. */
                private readonly ?object $tenant,

            ) {}

            /**
             * Resolve the tenant and increment the call counter.
             *
             * @return object|null
             */
            #[\Override]
            public function resolve(): ?object
            {
                $this->calls++;

                return $this->tenant;
            }
        };

        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;
        $app->instance(TenantResolver::class, $spy);

        // Flush any memo the scope captured before the spy was
        // bound — previous tests may have resolved the null
        // tenant against the NullTenantResolver default.
        $this->flushTenantScopeMemos();

        // Issue multiple queries against both scoped models — each
        // one invokes `TenantScope::apply`. Without memoisation the
        // spy would record one call per query.
        Role::all();
        Role::all();
        Role::query()->where('name', 'role-a')->get();
        Permission::all();
        Permission::query()->where('name', 'perm-a')->get();

        // One call per scope instance (Role + Permission each hold
        // their own global scope registration). That is O(models),
        // not O(queries) — the regression guard.
        static::assertLessThanOrEqual(2, $spy->calls);
        static::assertGreaterThan(0, $spy->calls);
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

        $this->bindTenantResolver($opaque);

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
            public function getKey(): string
            {
                return 'custom-tenant-42';
            }

            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'App\Tenancy\CustomTenant';
            }
        };

        Role::create([
            'name'        => 'custom-role',
            'guard_name'  => 'web',
            'tenant_type' => $customTenant->getMorphClass(),
            'tenant_id'   => (string) $customTenant->getKey(), // @phpstan-ignore cast.useless
        ]);
        Role::create(['name' => 'global-role', 'guard_name' => 'web']);

        $this->bindTenantResolver($customTenant);
        $this->flushTenantScopeMemos();

        $roles = Role::all();

        static::assertCount(2, $roles);
        static::assertTrue($roles->pluck('name')->contains('custom-role'));
        static::assertTrue($roles->pluck('name')->contains('global-role'));
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
            'guard_name'  => 'web',
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
            'guard_name'  => 'web',
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
            'guard_name'  => 'web',
            'tenant_type' => 'App\Tenant',
            'tenant_id'   => null,
        ]);
    }

    /**
     * Bind a custom tenant resolver that returns the given tenant.
     *
     * @param  object|null  $tenant
     * @return void
     */
    private function bindTenantResolver(?object $tenant): void
    {
        // @phpstan-ignore-next-line method.nonObject
        $this->app->singleton(TenantResolver::class, static function () use ($tenant): TenantResolver {

            /**
             * Test resolver that returns the captured tenant verbatim.
             */
            return new class ($tenant) implements TenantResolver {
                /**
                 * Create a new resolver wrapping a fixed tenant.
                 *
                 * @param  object|null  $tenant
                 * @return void
                 */
                public function __construct(

                    /** The tenant returned by every resolution call. */
                    private readonly ?object $tenant,

                ) {}

                /**
                 * Resolve the current tenant.
                 *
                 * @return object|null
                 */
                #[\Override]
                public function resolve(): ?object
                {
                    return $this->tenant;
                }
            };
        });

        $this->flushTenantScopeMemos();
    }

    /**
     * Flush the per-instance tenant memo on the global scopes registered on
     * `Role` and `Permission` so a re-bound resolver is observed on the next
     * query.
     *
     * @return void
     */
    private function flushTenantScopeMemos(): void
    {
        foreach ([Role::class, Permission::class] as $class) {
            /** @var \SineMacula\Laravel\Authorization\Scopes\TenantScope|null $scope */ // @phpstan-ignore varTag.type
            $scope = $class::getGlobalScope(TenantScope::class);

            $scope?->flushResolvedTenant();
        }
    }
}
