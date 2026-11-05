<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\SwitchableSubjectResolver;
use Tests\TestCase;

/**
 * Feature coverage for `TenantScope`: platform rows only without a subject or a
 * tenant, the subject's tenant read from the request's resolved-tenant holder,
 * and the refusal of tenants that cannot be matched to the rows they own.
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
        SwitchableSubjectResolver::$tenant = null;

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
     * With no subject, or a subject without a tenant, only platform-wide rows
     * are visible: no tenant never means every tenant.
     *
     * @return void
     */
    public function testNoSubjectOrNoTenantMeansPlatformRowsOnly(): void
    {
        $this->seedRows();

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver);

        self::assertSame(['platform-role'], $this->roleNames());
        self::assertSame(['platform-permission'], $this->permissionNames());

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver(new \stdClass));

        self::assertSame(['platform-role'], $this->roleNames());
        self::assertSame(['platform-permission'], $this->permissionNames());
    }

    /**
     * The tenant is the one the resolved subject carries.
     *
     * @return void
     */
    public function testTheTenantComesFromTheResolvedSubject(): void
    {
        [, $tenantB] = $this->seedRows();

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver(new \stdClass, $tenantB, 'admin', 'web'));

        self::assertSame(['b-role', 'platform-role'], $this->roleNames());
        self::assertSame(['b-permission', 'platform-permission'], $this->permissionNames());
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

        SwitchableSubjectResolver::$tenant = $tenantB;

        self::assertSame(['a-role', 'platform-role'], $this->roleNames());

        (new TenantScope)->flushResolvedTenant();

        self::assertSame(['b-role', 'platform-role'], $this->roleNames());
    }

    /**
     * The current tenant is the morph type and key of the tenant the scope
     * limits rows to, or null for the platform.
     *
     * @return void
     */
    public function testCurrentTenantIsTheTenantsMorphTypeAndKey(): void
    {
        [$tenantA] = $this->seedRows();

        self::assertNull(TenantScope::currentTenant());

        $this->useSwitchableResolver($tenantA);
        (new TenantScope)->flushResolvedTenant();

        self::assertSame([$tenantA->getMorphClass(), 'tenant-a'], TenantScope::currentTenant());
    }

    /**
     * Flushing the resolved tenant empties the resolution cache's memo, whose
     * entries were resolved under it.
     *
     * @return void
     */
    public function testFlushResolvedTenantEmptiesTheResolutionMemo(): void
    {
        $cache       = new ResolutionCache;
        $resolutions = 0;
        $resolve     = static function () use (&$resolutions): Resolution {
            $resolutions++;

            return new Resolution(['posts:read']);
        };

        $this->app?->instance(ResolutionCache::class, $cache);

        $cache->rememberPermissions(new Reference('user', 'user-1'), $resolve);
        $cache->rememberPermissions(new Reference('user', 'user-1'), $resolve);
        (new TenantScope)->flushResolvedTenant();
        $cache->rememberPermissions(new Reference('user', 'user-1'), $resolve);

        self::assertSame(2, $resolutions);
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

        $this->app?->instance(SubjectResolver::class, new SwitchableSubjectResolver);
        SwitchableSubjectResolver::$tenant = $tenantB;

        self::assertSame(['b-role', 'platform-role'], $this->roleNames());
        self::assertSame(['b-permission', 'platform-permission'], $this->permissionNames());
    }

    /**
     * A query on any scoped model the resolver runs while it resolves the
     * subject (a user model that eager-loads its roles and permissions, say)
     * sees platform rows only, so the resolver runs once instead of again for
     * each model, and the tenant it returns then scopes every later query.
     *
     * @return void
     */
    public function testAQueryRunWhileResolvingSeesPlatformRowsOnly(): void
    {
        [, $tenantB] = $this->seedRows();

        $resolver = new class ($tenantB) implements SubjectResolver {
            /** @var list<string> The role names the resolver's own query saw. */
            public array $seen = [];

            /** @var list<string> The permission names the resolver's own query saw. */
            public array $seenPermissions = [];

            /** @var int How many times the subject was resolved. */
            public int $resolutions = 0;

            /**
             * Create a new resolver for a fixed tenant.
             *
             * @param  object  $tenant
             */
            public function __construct(

                /** The tenant of the resolved subject. */
                private readonly object $tenant,
            ) {}

            /**
             * Query the roles and permissions, as loading a user with both
             * does, then resolve a subject in the tenant.
             *
             * @return \SineMacula\Laravel\Authorization\Subject
             */
            #[\Override]
            public function resolve(): Subject
            {
                $this->resolutions++;

                /** @var list<string> $names */
                $names      = Role::query()->orderBy('name')->pluck('name')->all();
                $this->seen = $names;

                /** @var list<string> $permissions */
                $permissions           = Permission::query()->orderBy('name')->pluck('name')->all();
                $this->seenPermissions = $permissions;

                return $this->forUser(new \stdClass);
            }

            /**
             * Make the given user the subject, in the tenant.
             *
             * @param  object  $user
             * @return \SineMacula\Laravel\Authorization\Subject
             */
            #[\Override]
            public function forUser(object $user): Subject
            {
                return new Subject($user, $user, $this->tenant);
            }
        };

        $this->app?->instance(SubjectResolver::class, $resolver);

        self::assertSame(['b-role', 'platform-role'], $this->roleNames());
        self::assertSame(['platform-role'], $resolver->seen);
        self::assertSame(['platform-permission'], $resolver->seenPermissions);
        self::assertSame(['b-permission', 'platform-permission'], $this->permissionNames());
        self::assertSame(1, $resolver->resolutions);
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

        Role::create(['name' => 'platform-role', 'guard' => 'web']);
        Permission::create(['name' => 'platform-permission', 'guard' => 'web']);

        foreach (['a' => $tenantA, 'b' => $tenantB] as $prefix => $tenant) {
            $owner = ['guard' => 'web', 'tenant_type' => $tenant->getMorphClass(), 'tenant_id' => $tenant->getKey()];

            Role::create(['name' => "{$prefix}-role"] + $owner);
            Permission::create(['name' => "{$prefix}-permission"] + $owner);
        }

        return [$tenantA, $tenantB];
    }

    /**
     * Bind the switchable subject resolver, starting with the given tenant.
     *
     * @param  object|null  $tenant
     * @return void
     */
    private function useSwitchableResolver(?object $tenant): void
    {
        SwitchableSubjectResolver::$tenant = $tenant;

        $this->app?->scoped(SubjectResolver::class, SwitchableSubjectResolver::class);
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
