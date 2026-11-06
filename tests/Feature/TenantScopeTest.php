<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
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
     * Below another tenant in the bound tree, a tenant sees its ancestors' rows
     * as well as its own and the platform's, and its chain lists it first.
     *
     * @return void
     */
    public function testATenantSeesItsAncestorsRows(): void
    {
        [$tenantA, $tenantB] = $this->seedRows();

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($tenantA), Reference::of($tenantB)));
        $this->useSwitchableResolver($tenantA);

        self::assertSame(['a-role', 'b-role', 'platform-role'], $this->roleNames());
        self::assertSame(['a-permission', 'b-permission', 'platform-permission'], $this->permissionNames());
        self::assertEquals([Reference::of($tenantA), Reference::of($tenantB)], TenantScope::currentChain()->tenants);

        $this->app?->instance(TenantTree::class, new StubTenantTree);

        self::assertEquals([Reference::of($tenantA)], TenantScope::refreshChain()->tenants);
        self::assertSame(['a-role', 'platform-role'], $this->roleNames());
    }

    /**
     * A query the tenant tree runs while it reads the ancestors sees platform
     * rows only, the chain it reads is held for the rest of the request, and a
     * refresh reads it again the same way.
     *
     * @return void
     */
    public function testAQueryRunWhileReadingTheAncestorsSeesPlatformRowsOnly(): void
    {
        [$tenantA] = $this->seedRows();

        $tree = new class implements TenantTree {
            /** @var list<list<string>> The role names each read of the ancestors saw. */
            public array $seen = [];

            /**
             * Query the roles, as a tree over the application's models might.
             *
             * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
             * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
             */
            #[\Override]
            public function ancestors(Reference $tenant): array
            {
                /** @var list<string> $names */
                $names        = Role::query()->orderBy('name')->pluck('name')->all();
                $this->seen[] = $names;

                return [];
            }

            /**
             * Determine whether the tenant is the other.
             *
             * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
             * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
             * @return bool
             */
            #[\Override]
            public function isWithin(Reference $tenant, Reference $ancestor): bool
            {
                return $tenant === $ancestor;
            }

            /**
             * Return no subtree; the test reads none.
             *
             * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
             * @return \Illuminate\Contracts\Database\Query\Builder
             */
            #[\Override]
            public function subtree(Reference $tenant): Builder
            {
                return DB::query();
            }
        };

        $this->app?->instance(TenantTree::class, $tree);
        $this->useSwitchableResolver($tenantA);

        self::assertSame(['a-role', 'platform-role'], $this->roleNames());
        self::assertSame(['a-role', 'platform-role'], $this->roleNames());
        self::assertSame([['platform-role']], $tree->seen);

        TenantScope::refreshChain();

        self::assertSame([['platform-role'], ['platform-role']], $tree->seen);
        self::assertEquals([Reference::of($tenantA)], TenantScope::currentChain()->tenants);
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
     * The current application is the one the resolved subject is on, or none.
     *
     * @return void
     */
    public function testCurrentApplicationIsTheSubjectsApplication(): void
    {
        self::assertNull(TenantScope::currentApplication());

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver(new \stdClass, null, 'admin'));
        (new TenantScope)->flushResolvedTenant();

        self::assertSame('admin', TenantScope::currentApplication());
    }

    /**
     * A change of the default guard, as Laravel's `auth:` middleware makes
     * during a request, reads the subject again, so an application named after
     * the guard is never held from the guard before.
     *
     * @return void
     */
    public function testAChangeOfDefaultGuardReadsTheApplicationAgain(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make('config');

        $this->app?->instance(SubjectResolver::class, new class implements SubjectResolver {
            /**
             * Resolve a subject on the application the default guard names.
             *
             * @return \SineMacula\Laravel\Authorization\Subject
             */
            #[\Override]
            public function resolve(): Subject
            {
                return $this->forUser(new \stdClass);
            }

            /**
             * Return the user as the subject, on the default guard's
             * application.
             *
             * @param  object  $user
             * @return \SineMacula\Laravel\Authorization\Subject
             */
            #[\Override]
            public function forUser(object $user): Subject
            {
                /** @var string $guard */
                $guard = config('auth.defaults.guard');

                return new Subject($user, $user, null, $guard);
            }
        });

        $config->set('auth.defaults.guard', 'web');

        self::assertSame('web', TenantScope::currentApplication());

        $config->set('auth.defaults.guard', 'admin');

        self::assertSame('admin', TenantScope::currentApplication());
        self::assertSame('admin', $this->app?->make(ResolvedTenant::class)->guard);
    }

    /**
     * Within a tenant and application, queries and the current application are
     * theirs; afterwards the request's are restored, also when the callback
     * throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithinRunsUnderAnotherTenantAndApplication(): void
    {
        [$tenantA, $tenantB] = $this->seedRows();

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver(new \stdClass, $tenantA, 'web'));

        $inside = TenantScope::within($tenantB, 'admin', fn (): array => [TenantScope::currentApplication(), $this->roleNames()]);

        self::assertSame(['admin', ['b-role', 'platform-role']], $inside);
        self::assertSame('web', TenantScope::currentApplication());
        self::assertSame(['a-role', 'platform-role'], $this->roleNames());

        try {
            TenantScope::within(null, 'admin', static fn (): never => self::refuse());
        } catch (\RuntimeException) {
            self::assertSame('web', TenantScope::currentApplication());
        }
    }

    /**
     * What is resolved within another application is not served to the request
     * afterwards, and without a resolution cache bound, within runs all the
     * same.
     *
     * @return void
     */
    public function testWithinLeavesNothingResolvedInsideToTheRequest(): void
    {
        $user = StubIdentity::query()->create(['id' => 'user-1']);

        Permission::create(['name' => 'admin:access']);
        $user->givePermission('admin:access', application: 'admin');

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, null, 'web'));

        self::assertSame(['admin:access'], TenantScope::within(null, 'admin', static fn (): array => $user->getPermissions()));
        self::assertSame([], $user->getPermissions());

        $this->app?->offsetUnset(ResolutionCache::class);

        self::assertSame('admin', TenantScope::within(null, 'admin', static fn (): ?string => TenantScope::currentApplication()));
    }

    /**
     * Run while the subject is being resolved, queries within see the tenant
     * and application given, a query after it still sees platform rows only,
     * and the holder is then resolved as usual.
     *
     * @return void
     */
    public function testWithinWhileResolvingSeesItsTenantAndApplication(): void
    {
        [, $tenantB] = $this->seedRows();

        $resolver = new class ($tenantB) implements SubjectResolver {
            /**
             * Create a resolver that queries within the given tenant.
             *
             * @param  object  $tenant
             */
            public function __construct(

                /** The tenant the query within runs in. */
                private readonly object $tenant,
            ) {}

            /** @var array{0: string|null, 1: array<int, string>}|null The application and role names seen within, while resolving. */
            public ?array $seen = null;

            /** @var array<int, string>|null The role names seen after within, still while resolving. */
            public ?array $after = null;

            /**
             * Query the roles within another application, then resolve.
             *
             * @return \SineMacula\Laravel\Authorization\Subject
             */
            #[\Override]
            public function resolve(): Subject
            {
                /** @var array{0: string|null, 1: array<int, string>} $seen */
                $seen = TenantScope::within(
                    $this->tenant,
                    'admin',
                    static fn (): array => [TenantScope::currentApplication(), Role::query()->orderBy('name')->pluck('name')->all()],
                );
                $this->seen = $seen;

                /** @var array<int, string> $after */
                $after       = Role::query()->orderBy('name')->pluck('name')->all();
                $this->after = $after;

                return $this->forUser(new \stdClass);
            }

            /**
             * Return the user as the subject, on the web application.
             *
             * @param  object  $user
             * @return \SineMacula\Laravel\Authorization\Subject
             */
            #[\Override]
            public function forUser(object $user): Subject
            {
                return new Subject($user, $user, null, 'web');
            }
        };

        $this->app?->instance(SubjectResolver::class, $resolver);

        self::assertSame('web', TenantScope::currentApplication());
        self::assertSame(['admin', ['b-role', 'platform-role']], $resolver->seen);
        self::assertSame(['platform-role'], $resolver->after);
        self::assertSame(['platform-role'], $this->roleNames());
        self::assertSame('web', TenantScope::currentApplication());
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

    /**
     * Throw, as a callback that fails would.
     *
     * @return never
     *
     * @throws \RuntimeException
     */
    private static function refuse(): never
    {
        throw new \RuntimeException('Refused.');
    }
}
