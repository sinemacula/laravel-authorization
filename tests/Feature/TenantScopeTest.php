<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\SwitchableTenantResolver;
use Tests\TestCase;

/**
 * Feature coverage for `TenantScope`: platform rows only without a tenant, the
 * tenant read from the request's resolved-tenant holder, and the refusal of
 * tenants that cannot be matched to the rows they own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(TenantScope::class)]
#[CoversClass(ResolvedTenant::class)]
#[CoversClass(InvalidTenantException::class)]
final class TenantScopeTest extends TestCase
{
    /**
     * Reset the switchable tenant.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        SwitchableTenantResolver::$tenant = null;

        parent::tearDown();
    }

    /**
     * Without a tenant only platform-wide roles and permissions are visible,
     * never another tenant's.
     *
     * @return void
     */
    public function testWithoutTenantOnlyPlatformRowsAreVisible(): void
    {
        $this->seedRows();

        self::assertSame(['platform-role'], $this->roleNames());
        self::assertSame(['platform-permission'], $this->permissionNames());
    }

    /**
     * With a tenant the platform-wide rows and the tenant's own rows are
     * visible, and no other tenant's.
     *
     * @return void
     */
    public function testTenantSeesPlatformAndOwnRows(): void
    {
        [$tenantA] = $this->seedRows();

        $this->useSwitchableResolver($tenantA);

        self::assertSame(['a-role', 'platform-role'], $this->roleNames());
        self::assertSame(['a-permission', 'platform-permission'], $this->permissionNames());
    }

    /**
     * The scope reads the tenant resolved for the request, so a tenant changed
     * mid-request is only seen after `flushResolvedTenant()`.
     *
     * @return void
     */
    public function testFlushResolvedTenantAsksTheResolverAgain(): void
    {
        [$tenantA, $tenantB] = $this->seedRows();

        $this->useSwitchableResolver($tenantA);

        self::assertSame(['a-role', 'platform-role'], $this->roleNames());

        SwitchableTenantResolver::$tenant = $tenantB;

        self::assertSame(['a-role', 'platform-role'], $this->roleNames());

        (new TenantScope)->flushResolvedTenant();

        self::assertSame(['b-role', 'platform-role'], $this->roleNames());
    }

    /**
     * A resolver bound after the tenant was resolved is asked on the next
     * query, without flushing the resolved tenant.
     *
     * @return void
     */
    public function testRebindingTheResolverIsSeenOnTheNextQuery(): void
    {
        [$tenantA, $tenantB] = $this->seedRows();

        $this->useSwitchableResolver($tenantA);

        self::assertSame(['a-role', 'platform-role'], $this->roleNames());

        $this->app?->instance(TenantResolver::class, new SwitchableTenantResolver);
        SwitchableTenantResolver::$tenant = $tenantB;

        self::assertSame(['b-role', 'platform-role'], $this->roleNames());
        self::assertSame(['b-permission', 'platform-permission'], $this->permissionNames());
    }

    /**
     * A tenant model that has not been saved has no key, and is refused rather
     * than matched as `tenant_id = ''`.
     *
     * @return void
     */
    public function testUnsavedTenantModelIsRefused(): void
    {
        $this->useSwitchableResolver(new StubTenant);

        $this->expectException(InvalidTenantException::class);
        $this->expectExceptionMessage('Tenant ' . StubTenant::class . ' has no key, so it cannot be matched to the rows it owns.');

        Role::query()->get();
    }

    /**
     * An `AuthorizableTenant` whose key is an empty string is refused.
     *
     * @return void
     */
    public function testAuthorizableTenantWithEmptyKeyIsRefused(): void
    {
        $tenant = $this->authorizableTenant('');

        $this->expectException(InvalidTenantException::class);
        $this->expectExceptionMessage('Tenant ' . $tenant::class . ' has no key, so it cannot be matched to the rows it owns.');

        TenantScope::extractTenantPair($tenant);
    }

    /**
     * A keyless tenant passed to the `forTenant` local scope is refused too.
     *
     * @return void
     */
    public function testForTenantRefusesKeylessTenant(): void
    {
        $this->expectException(InvalidTenantException::class);
        $this->expectExceptionMessage('has no key');

        Role::query()->withoutGlobalScope(TenantScope::class)->forTenant(new StubTenant)->get();
    }

    /**
     * An object that is neither a model nor an `AuthorizableTenant` is refused.
     *
     * @return void
     */
    public function testNonTenantObjectIsRefused(): void
    {
        $this->expectException(InvalidTenantException::class);
        $this->expectExceptionMessage('Tenant must be an Eloquent Model or implement ' . AuthorizableTenant::class . '. Got stdClass.');

        TenantScope::extractTenantPair(new \stdClass);
    }

    /**
     * A model tenant and an `AuthorizableTenant` both yield their morph class
     * and their key as a string, including an integer key of zero.
     *
     * @return void
     */
    public function testTenantPairIsMorphClassAndStringKey(): void
    {
        $model = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        self::assertSame([$model->getMorphClass(), 'tenant-a'], TenantScope::extractTenantPair($model));
        self::assertSame(['custom-tenant', '0'], TenantScope::extractTenantPair($this->authorizableTenant(0)));
    }

    /**
     * Seed one platform-wide role and permission, and one of each owned by each
     * of two tenants.
     *
     * @return array{0: \Tests\Feature\Stubs\StubTenant, 1: \Tests\Feature\Stubs\StubTenant}
     */
    private function seedRows(): array
    {
        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);
        $tenantB = StubTenant::create(['id' => 'tenant-b', 'name' => 'Tenant B']);

        Role::create(['name' => 'platform-role', 'guard_name' => 'web']);
        Permission::create(['name' => 'platform-permission', 'guard_name' => 'web']);

        foreach (['a' => $tenantA, 'b' => $tenantB] as $prefix => $tenant) {
            $owner = ['guard_name' => 'web', 'tenant_type' => $tenant->getMorphClass(), 'tenant_id' => $tenant->getKey()];

            Role::create(['name' => "{$prefix}-role"] + $owner);
            Permission::create(['name' => "{$prefix}-permission"] + $owner);
        }

        return [$tenantA, $tenantB];
    }

    /**
     * Bind the switchable tenant resolver, starting with the given tenant.
     *
     * @param  object|null  $tenant
     * @return void
     */
    private function useSwitchableResolver(?object $tenant): void
    {
        SwitchableTenantResolver::$tenant = $tenant;

        $this->app?->scoped(TenantResolver::class, SwitchableTenantResolver::class);
    }

    /**
     * Return the visible role names, sorted.
     *
     * @return array<int, string>
     */
    private function roleNames(): array
    {
        /** @var array<int, string> */
        return Role::query()->orderBy('name')->pluck('name')->all();
    }

    /**
     * Return the visible permission names, sorted.
     *
     * @return array<int, string>
     */
    private function permissionNames(): array
    {
        /** @var array<int, string> */
        return Permission::query()->orderBy('name')->pluck('name')->all();
    }

    /**
     * Build an `AuthorizableTenant` with the given key.
     *
     * @param  int|string  $key
     * @return \SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant
     */
    private function authorizableTenant(int|string $key): AuthorizableTenant
    {
        return new class ($key) implements AuthorizableTenant {
            /**
             * Create a new tenant with a fixed key.
             *
             * @param  int|string  $key
             */
            public function __construct(

                /** The tenant's key. */
                private readonly int|string $key,
            ) {}

            /**
             * @return int|string
             */
            #[\Override]
            public function getKey(): int|string
            {
                return $this->key;
            }

            /**
             * @return string
             */
            #[\Override]
            public function getMorphClass(): string
            {
                return 'custom-tenant';
            }
        };
    }
}
