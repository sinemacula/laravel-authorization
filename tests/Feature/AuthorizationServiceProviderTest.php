<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepositoryImplementation;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Resolvers\NullTenantResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\SwitchableTenantResolver;
use Tests\TestCase;

/**
 * Feature coverage for the service provider's request and job lifetimes.
 *
 * Every binding that holds state for one request or job is bound with
 * `scoped()`, so a queue worker running job after job in one container, and
 * Octane running request after request on cloned sandboxes, never see another
 * job's or request's tenant, cached grants or last decision.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(GateRegistrar::class)]
#[CoversClass(BladeDirectiveRegistrar::class)]
#[CoversClass(EventListenerRegistrar::class)]
#[CoversClass(TenantScope::class)]
#[CoversClass(ResolvedTenant::class)]
#[CoversClass(ResolutionCache::class)]
#[CoversClass(LastDecisionStore::class)]
#[CoversClass(AuthorizationManager::class)]
final class AuthorizationServiceProviderTest extends TestCase
{
    /**
     * Configure the switchable tenant resolver, as an application configures
     * its own, and register the provider again so the binding uses it.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $app = $this->application();

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);
        $config->set('authorization.tenant_resolver', SwitchableTenantResolver::class);

        (new AuthorizationServiceProvider($app))->register();
    }

    /**
     * Reset the switchable tenant and the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        SwitchableTenantResolver::$tenant = null;
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Every binding that holds request or job state is shared within a job and
     * rebuilt for the next one.
     *
     * @return void
     */
    public function testRequestStateBindingsAreRebuiltForEachJob(): void
    {
        $app       = $this->application();
        $abstracts = [
            PrincipalResolver::class,
            TenantResolver::class,
            ResolvedTenant::class,
            ResolutionCache::class,
            PolicyResolver::class,
            LastDecisionStore::class,
            PolicyEvaluator::class,
            'authorization',
            AuthorizationManager::class,
        ];

        foreach ($abstracts as $abstract) {
            $first = $app->make($abstract);

            self::assertIsObject($first);
            self::assertSame($first, $app->make($abstract), "{$abstract} should be shared within a job.");

            $this->startNextJob();

            self::assertNotSame($first, $app->make($abstract), "{$abstract} should be rebuilt for the next job.");
        }

        self::assertSame($app->make('authorization'), $app->make(AuthorizationManager::class));
    }

    /**
     * The configured tenant resolver class is the one bound.
     *
     * @return void
     */
    public function testConfiguredTenantResolverIsBound(): void
    {
        self::assertInstanceOf(SwitchableTenantResolver::class, $this->application()->make(TenantResolver::class));
    }

    /**
     * A null `tenant_resolver` means no tenant resolver and binds the null
     * resolver, under which only platform-wide rows are visible.
     *
     * @return void
     */
    public function testNullTenantResolverConfigBindsTheNullResolver(): void
    {
        $app = $this->application();

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);
        $config->set('authorization.tenant_resolver', null);

        (new AuthorizationServiceProvider($app))->register();

        self::assertInstanceOf(NullTenantResolver::class, $app->make(TenantResolver::class));

        Role::create(['name' => 'platform', 'guard_name' => 'web']);
        Role::create(['name' => 'owned', 'guard_name' => 'web', 'tenant_type' => 'tenant', 'tenant_id' => 't-1']);

        self::assertSame(['platform'], Role::query()->pluck('name')->all());
    }

    /**
     * Registering the provider binds the tenant resolver and the resolved
     * tenant without building either, so no application resolver runs before
     * the first query.
     *
     * @return void
     */
    public function testRegisteringDoesNotResolveTheTenantResolver(): void
    {
        $app = new Application(\dirname(__DIR__, 2));

        try {
            $app->instance('config', new ConfigRepositoryImplementation([
                'authorization' => ['tenant_resolver' => SwitchableTenantResolver::class],
            ]));

            (new AuthorizationServiceProvider($app))->register();

            self::assertTrue($app->bound(TenantResolver::class));
            self::assertTrue($app->bound(ResolvedTenant::class));
            self::assertFalse($app->resolved(TenantResolver::class));
            self::assertFalse($app->resolved(ResolvedTenant::class));
        } finally {
            Container::setInstance($this->application());
        }
    }

    /**
     * Rebinding the tenant resolver after a tenant was resolved is seen by the
     * next query, which asks the new resolver.
     *
     * @return void
     */
    public function testRebindingTheTenantResolverIsSeenByTheNextQuery(): void
    {
        [$tenantA, $tenantB] = $this->seedTwoTenants();

        $app = $this->application();

        SwitchableTenantResolver::$tenant = $tenantA;

        self::assertSame(['a-editor', 'global', 'on-call'], $this->visibleRoleNames());

        $app->instance(TenantResolver::class, new class ($tenantB) implements TenantResolver {
            /**
             * Create a new resolver for a fixed tenant.
             *
             * @param  object  $tenant
             */
            public function __construct(

                /** The tenant this resolver returns. */
                private readonly object $tenant,
            ) {}

            /**
             * Resolve the fixed tenant.
             *
             * @return object
             */
            #[\Override]
            public function resolve(): object
            {
                return $this->tenant;
            }
        });

        self::assertSame(['b-editor', 'global', 'on-call'], $this->visibleRoleNames());
    }

    /**
     * Two queue jobs on one container: each sees its own tenant's rows, the
     * grant that expired between them is gone, and the second job does not see
     * the first one's last decision.
     *
     * @return void
     */
    public function testQueueJobsDoNotShareTenantCachedGrantsOrLastDecision(): void
    {
        [$tenantA, $tenantB, $userId] = $this->seedTwoTenants();

        // Job 1, for tenant A.
        SwitchableTenantResolver::$tenant = $tenantA;

        self::assertSame(['a-editor', 'global', 'on-call'], $this->visibleRoleNames());
        self::assertSame(['a-editor', 'on-call'], $this->rolesOf($userId));

        Authorization::for($this->identity($userId))->evaluate('posts:read');

        self::assertNotNull(Authorization::lastDecision());

        // The temporary grant expires between the two jobs.
        Carbon::setTestNow('2026-07-01 12:10:00');

        // Job 2, for tenant B.
        $this->startNextJob();
        SwitchableTenantResolver::$tenant = $tenantB;

        self::assertSame(['b-editor', 'global', 'on-call'], $this->visibleRoleNames());
        self::assertSame(['b-editor'], $this->rolesOf($userId));
        self::assertNull(Authorization::lastDecision());

        // Job 3, with no tenant: platform rows only.
        $this->startNextJob();
        SwitchableTenantResolver::$tenant = null;

        self::assertSame(['global', 'on-call'], $this->visibleRoleNames());
        self::assertSame([], $this->rolesOf($userId));
    }

    /**
     * A grant that expires while one long job is running stops counting within
     * that job.
     *
     * @return void
     */
    public function testGrantExpiringWithinOneJobLapses(): void
    {
        [$tenantA, , $userId] = $this->seedTwoTenants();

        SwitchableTenantResolver::$tenant = $tenantA;

        self::assertSame(['a-editor', 'on-call'], $this->rolesOf($userId));

        Carbon::setTestNow('2026-07-01 12:10:00');

        self::assertSame(['a-editor'], $this->rolesOf($userId));
    }

    /**
     * Octane-style requests: each request runs on a fresh clone of the booted
     * application, which can reuse the previous sandbox's object id. Neither
     * the tenant nor the last decision reaches the next request.
     *
     * @return void
     */
    public function testOctaneSandboxesDoNotShareTenantOrLastDecision(): void
    {
        [$tenantA, $tenantB, $userId] = $this->seedTwoTenants();

        $base = $this->application();

        $first = $this->inSandbox($base, function () use ($tenantA, $userId): array {
            SwitchableTenantResolver::$tenant = $tenantA;

            Authorization::for($this->identity($userId))->evaluate('posts:read');

            return [$this->visibleRoleNames(), $this->rolesOf($userId), Authorization::lastDecision()];
        });

        self::assertSame(['a-editor', 'global', 'on-call'], $first[0]);
        self::assertSame(['a-editor', 'on-call'], $first[1]);
        self::assertNotNull($first[2]);

        $second = $this->inSandbox($base, function () use ($tenantB, $userId): array {
            SwitchableTenantResolver::$tenant = $tenantB;

            return [$this->visibleRoleNames(), $this->rolesOf($userId), Authorization::lastDecision()];
        });

        self::assertSame(['b-editor', 'global', 'on-call'], $second[0]);
        self::assertSame(['b-editor', 'on-call'], $second[1]);
        self::assertNull($second[2]);
    }

    /**
     * Seed two tenants, a platform role, a temporary platform role, one role
     * owned by each tenant, and one identity holding every role but the plain
     * platform one. The temporary grant expires at 12:05.
     *
     * @return array{0: \Tests\Feature\Stubs\StubTenant, 1: \Tests\Feature\Stubs\StubTenant, 2: string}
     */
    private function seedTwoTenants(): array
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        $tenantA = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);
        $tenantB = StubTenant::create(['id' => 'tenant-b', 'name' => 'Tenant B']);

        Role::create(['name' => 'global', 'guard_name' => 'web']);
        $onCall  = Role::create(['name' => 'on-call', 'guard_name' => 'web']);
        $aEditor = Role::create(['name' => 'a-editor', 'guard_name' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => 'tenant-a']);
        $bEditor = Role::create(['name' => 'b-editor', 'guard_name' => 'web', 'tenant_type' => $tenantB->getMorphClass(), 'tenant_id' => 'tenant-b']);

        $user = StubIdentity::create(['id' => 'user-1', 'name' => 'Alice']);
        $user->assignRole($onCall, Carbon::parse('2026-07-01 12:05:00'));
        $user->assignRole($aEditor);
        $user->assignRole($bEditor);

        // Start the first job with nothing resolved during seeding.
        $this->startNextJob();

        return [$tenantA, $tenantB, 'user-1'];
    }

    /**
     * Run the reset the queue worker runs before each job.
     *
     * @return void
     */
    private function startNextJob(): void
    {
        $worker = $this->application()->make('queue.worker');

        /** @var callable $reset */
        $reset = (new \ReflectionProperty($worker, 'resetScope'))->getValue($worker);
        $reset();
    }

    /**
     * Run one request the way Octane does: on a clone of the booted application
     * set as the current container, discarded afterwards, after which the
     * booted application forgets its scoped instances.
     *
     * @template TResult
     *
     * @param  \Illuminate\Foundation\Application  $base
     * @param  \Closure(): TResult  $request
     * @return TResult
     */
    private function inSandbox(Application $base, \Closure $request): mixed
    {
        $sandbox = clone $base;
        $sandbox->instance('app', $sandbox);
        $sandbox->instance(Container::class, $sandbox);

        Container::setInstance($sandbox);
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication($sandbox);

        try {
            return $request();
        } finally {
            Container::setInstance($base);
            Facade::clearResolvedInstances();
            Facade::setFacadeApplication($base);
            $base->forgetScopedInstances();
        }
    }

    /**
     * Return the names of the roles the tenant scope lets through, sorted.
     *
     * @return array<int, string>
     */
    private function visibleRoleNames(): array
    {
        /** @var array<int, string> */
        return Role::query()->orderBy('name')->pluck('name')->all();
    }

    /**
     * Return the roles of a freshly loaded identity, sorted, as a new job or
     * request would load it.
     *
     * @param  string  $userId
     * @return array<int, string>
     */
    private function rolesOf(string $userId): array
    {
        $roles = $this->identity($userId)->getRoles();
        \sort($roles);

        return $roles;
    }

    /**
     * Load an identity afresh.
     *
     * @param  string  $userId
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function identity(string $userId): StubIdentity
    {
        return StubIdentity::query()->findOrFail($userId);
    }

    /**
     * Return the booted application.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function application(): Application
    {
        $app = $this->app;

        self::assertInstanceOf(Application::class, $app);

        return $app;
    }
}
