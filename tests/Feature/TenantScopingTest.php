<?php

declare(strict_types = 1);

namespace Tests\Feature;

use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for row-level multi-tenant role and permission
 * scoping.
 *
 * Verifies that the `TenantScope` global scope, `TenantResolver`
 * contract, and the tenant ownership helpers on `Role` and
 * `Permission` behave correctly under various tenant contexts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[\PHPUnit\Framework\Attributes\CoversNothing]
class TenantScopingTest extends TestCase
{
    public function testNullResolverShowsAllRoles(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Role::create(['name' => 'global-role', 'guard_name' => 'web']);
        Role::create(['name' => 'tenant-role', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey()]);

        static::assertCount(2, Role::all());
    }

    public function testNullResolverShowsAllPermissions(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Permission::create(['name' => 'global-perm', 'guard_name' => 'web']);
        Permission::create(['name' => 'tenant-perm', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey()]);

        static::assertCount(2, Permission::all());
    }

    public function testActiveTenantSeesGlobalAndOwnRoles(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);
        $tenantB = StubTenant::create(['id' => 'tenant-b', 'name' => 'Tenant B']);

        Role::create(['name' => 'global-role', 'guard_name' => 'web']);
        Role::create(['name' => 'role-a', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey()]);
        Role::create(['name' => 'role-b', 'guard_name' => 'web', 'tenant_type' => $tenantB->getMorphClass(), 'tenant_id' => (string) $tenantB->getKey()]);

        $this->bindTenantResolver($tenantA);

        $roles = Role::all();

        static::assertCount(2, $roles);
        static::assertTrue($roles->pluck('name')->contains('global-role'));
        static::assertTrue($roles->pluck('name')->contains('role-a'));
        static::assertFalse($roles->pluck('name')->contains('role-b'));
    }

    public function testDifferentTenantRolesAreInvisible(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);
        $tenantB = StubTenant::create(['id' => 'tenant-b', 'name' => 'Tenant B']);

        Role::create(['name' => 'role-b', 'guard_name' => 'web', 'tenant_type' => $tenantB->getMorphClass(), 'tenant_id' => (string) $tenantB->getKey()]);

        $this->bindTenantResolver($tenantA);

        static::assertCount(0, Role::all());
    }

    public function testGlobalRolesAlwaysVisibleRegardlessOfTenant(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Role::create(['name' => 'global-role', 'guard_name' => 'web']);

        $this->bindTenantResolver($tenantA);

        $roles = Role::all();

        static::assertCount(1, $roles);
        static::assertSame('global-role', $roles->first()->name);
    }

    public function testActiveTenantSeesGlobalAndOwnPermissions(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);
        $tenantB = StubTenant::create(['id' => 'tenant-b', 'name' => 'Tenant B']);

        Permission::create(['name' => 'global-perm', 'guard_name' => 'web']);
        Permission::create(['name' => 'perm-a', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey()]);
        Permission::create(['name' => 'perm-b', 'guard_name' => 'web', 'tenant_type' => $tenantB->getMorphClass(), 'tenant_id' => (string) $tenantB->getKey()]);

        $this->bindTenantResolver($tenantA);

        $perms = Permission::all();

        static::assertCount(2, $perms);
        static::assertTrue($perms->pluck('name')->contains('global-perm'));
        static::assertTrue($perms->pluck('name')->contains('perm-a'));
        static::assertFalse($perms->pluck('name')->contains('perm-b'));
    }

    public function testResolveByNameReturnsTenantScopedRole(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        // Create a global role and a tenant-owned role with the
        // same name but different guard to avoid the unique constraint.
        Role::create(['name' => 'editor', 'guard_name' => null]);
        Role::create(['name' => 'editor', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey()]);

        $this->bindTenantResolver($tenantA);

        $resolved = Role::resolveByName('editor', 'web');

        static::assertTrue($resolved->isTenantOwned());
        static::assertSame((string) $tenantA->getKey(), $resolved->tenant_id);
    }

    public function testResolveByNameReturnsTenantScopedPermission(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Permission::create(['name' => 'posts:edit', 'guard_name' => null]);
        Permission::create(['name' => 'posts:edit', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey()]);

        $this->bindTenantResolver($tenantA);

        $resolved = Permission::resolveByName('posts:edit', 'web');

        static::assertTrue($resolved->isTenantOwned());
        static::assertSame((string) $tenantA->getKey(), $resolved->tenant_id);
    }

    public function testCreatingRoleWithTenantPersistsCorrectly(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $role = Role::create([
            'name'        => 'tenant-editor',
            'guard_name'  => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(),
        ]);

        static::assertSame($tenantA->getMorphClass(), $role->tenant_type);
        static::assertSame((string) $tenantA->getKey(), $role->tenant_id);

        $fresh = Role::withoutGlobalScopes()->find($role->getKey());

        static::assertNotNull($fresh);
        static::assertSame($tenantA->getMorphClass(), $fresh->tenant_type);
        static::assertSame((string) $tenantA->getKey(), $fresh->tenant_id);
    }

    public function testCreatingPermissionWithTenantPersistsCorrectly(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $perm = Permission::create([
            'name'        => 'tenant-perm',
            'guard_name'  => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(),
        ]);

        static::assertSame($tenantA->getMorphClass(), $perm->tenant_type);
        static::assertSame((string) $tenantA->getKey(), $perm->tenant_id);
    }

    public function testIsGlobalReturnsTrueForGlobalRole(): void
    {
        $role = Role::create(['name' => 'global', 'guard_name' => 'web']);

        static::assertTrue($role->isGlobal());
        static::assertFalse($role->isTenantOwned());
    }

    public function testIsTenantOwnedReturnsTrueForTenantRole(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $role = Role::create([
            'name'        => 'editor',
            'guard_name'  => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(),
        ]);

        static::assertTrue($role->isTenantOwned());
        static::assertFalse($role->isGlobal());
    }

    public function testIsGlobalReturnsTrueForGlobalPermission(): void
    {
        $perm = Permission::create(['name' => 'global-perm', 'guard_name' => 'web']);

        static::assertTrue($perm->isGlobal());
        static::assertFalse($perm->isTenantOwned());
    }

    public function testIsTenantOwnedReturnsTrueForTenantPermission(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $perm = Permission::create([
            'name'        => 'posts:edit',
            'guard_name'  => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(),
        ]);

        static::assertTrue($perm->isTenantOwned());
        static::assertFalse($perm->isGlobal());
    }

    public function testScopeForTenantFiltersRolesByTenant(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);
        $tenantB = StubTenant::create(['id' => 'tenant-b', 'name' => 'Tenant B']);

        Role::create(['name' => 'global', 'guard_name' => 'web']);
        Role::create(['name' => 'role-a', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey()]);
        Role::create(['name' => 'role-b', 'guard_name' => 'web', 'tenant_type' => $tenantB->getMorphClass(), 'tenant_id' => (string) $tenantB->getKey()]);

        $roles = Role::forTenant($tenantA)->get();

        static::assertCount(1, $roles);
        static::assertSame('role-a', $roles->first()->name);
    }

    public function testScopeGlobalOnlyFiltersRoles(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Role::create(['name' => 'global', 'guard_name' => 'web']);
        Role::create(['name' => 'role-a', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey()]);

        $roles = Role::globalOnly()->get();

        static::assertCount(1, $roles);
        static::assertSame('global', $roles->first()->name);
    }

    public function testScopeForTenantFiltersPermissionsByTenant(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);
        $tenantB = StubTenant::create(['id' => 'tenant-b', 'name' => 'Tenant B']);

        Permission::create(['name' => 'global-perm', 'guard_name' => 'web']);
        Permission::create(['name' => 'perm-a', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey()]);
        Permission::create(['name' => 'perm-b', 'guard_name' => 'web', 'tenant_type' => $tenantB->getMorphClass(), 'tenant_id' => (string) $tenantB->getKey()]);

        $perms = Permission::forTenant($tenantA)->get();

        static::assertCount(1, $perms);
        static::assertSame('perm-a', $perms->first()->name);
    }

    public function testScopeGlobalOnlyFiltersPermissions(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Permission::create(['name' => 'global-perm', 'guard_name' => 'web']);
        Permission::create(['name' => 'perm-a', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey()]);

        $perms = Permission::globalOnly()->get();

        static::assertCount(1, $perms);
        static::assertSame('global-perm', $perms->first()->name);
    }

    public function testIdentityWithTenantRoleGetsCorrectPermissions(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $role = Role::create([
            'name'        => 'editor',
            'guard_name'  => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(),
        ]);

        $perm = Permission::create([
            'name'        => 'posts:edit',
            'guard_name'  => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(),
        ]);

        $role->givePermission($perm);

        $identity = StubIdentity::create(['id' => 'user-1', 'name' => 'Alice']);
        $identity->assignRole($role);

        $this->bindTenantResolver($tenantA);

        static::assertTrue($identity->hasRole('editor'));
        static::assertTrue($identity->hasPermission('posts:edit'));
    }

    public function testTenantRelationResolvesOnRole(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $role = Role::create([
            'name'        => 'editor',
            'guard_name'  => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(),
        ]);

        $resolved = $role->tenant;

        static::assertNotNull($resolved);
        static::assertSame('tenant-a', (string) $resolved->getKey());
    }

    public function testTenantRelationReturnsNullForGlobalRole(): void
    {
        $role = Role::create(['name' => 'global', 'guard_name' => 'web']);

        static::assertNull($role->tenant);
    }

    public function testTenantRelationResolvesOnPermission(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $perm = Permission::create([
            'name'        => 'posts:edit',
            'guard_name'  => 'web',
            'tenant_type' => $tenantA->getMorphClass(),
            'tenant_id'   => (string) $tenantA->getKey(),
        ]);

        $resolved = $perm->tenant;

        static::assertNotNull($resolved);
        static::assertSame('tenant-a', (string) $resolved->getKey());
    }

    public function testInvalidTenantResolverConfigThrows(): void
    {
        $this->app['config']->set('authorization.tenant_resolver', 'NonExistent\Class');

        $this->expectException(\SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessageMatches('/tenant_resolver/');

        /** @var array<string, mixed> $config */
        $config = $this->app['config']->get('authorization', []);

        \SineMacula\Laravel\Authorization\Config\ConfigValidator::validate($config, $this->app);
    }

    public function testNullTenantResolverConfigPassesValidation(): void
    {
        $this->app['config']->set('authorization.tenant_resolver', null);

        /** @var array<string, mixed> $config */
        $config = $this->app['config']->get('authorization', []);

        \SineMacula\Laravel\Authorization\Config\ConfigValidator::validate($config, $this->app);

        static::assertTrue(true);
    }

    /**
     * The `TenantResolver` is consulted at most once per scope
     * instance per container lifetime — a spy resolver wrapping a
     * concrete tenant records one `resolve()` invocation regardless
     * of how many Eloquent queries the scope filters (issue #103).
     *
     * @return void
     */
    public function testTenantResolverIsMemoisedAcrossQueries(): void
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        Role::create(['name' => 'role-a', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey()]);
        Role::create(['name' => 'global-role', 'guard_name' => 'web']);
        Permission::create(['name' => 'perm-a', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => (string) $tenantA->getKey()]);

        $spy = new class ($tenantA) implements TenantResolver {
            public int $calls = 0;

            public function __construct(private readonly ?object $tenant) {}

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
     * A resolver that returns an object which is neither an
     * Eloquent `Model` nor an `AuthorizableTenant` implementer is
     * refused at the scope boundary with `InvalidTenantException`
     * (issue #104) — no silent `spl_object_hash` fallback.
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
     * A custom tenant implementing `AuthorizableTenant` is accepted
     * by the scope and matches rows written with the contract's
     * `getMorphClass()` / `getKey()` values (issue #104).
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
            'tenant_id'   => (string) $customTenant->getKey(),
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
     * Persisting a Role with only `tenant_type` (tenant_id null)
     * raises `InvalidTenantColumnsException` before the row hits
     * the database (issue #105).
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
     * The inverse case — `tenant_id` set with `tenant_type` null —
     * is refused with the same exception (issue #105).
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
     * Permissions carry the same tenant-column invariant (issue
     * #105).
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
        $this->app->singleton(TenantResolver::class, static function () use ($tenant): TenantResolver {
            return new class ($tenant) implements TenantResolver {
                public function __construct(private readonly ?object $tenant) {}

                public function resolve(): ?object
                {
                    return $this->tenant;
                }
            };
        });

        $this->flushTenantScopeMemos();
    }

    /**
     * Flush the per-instance tenant memo on the global scopes
     * registered on `Role` and `Permission` so a re-bound resolver
     * is observed on the next query.
     *
     * @return void
     */
    private function flushTenantScopeMemos(): void
    {
        foreach ([Role::class, Permission::class] as $class) {
            /** @var \SineMacula\Laravel\Authorization\Scopes\TenantScope|null $scope */
            $scope = $class::getGlobalScope(TenantScope::class);

            $scope?->flushResolvedTenant();
        }
    }
}
