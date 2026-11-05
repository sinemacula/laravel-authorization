<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepositoryImplementation;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Http\Kernel as HttpKernelContract;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Routing\Router;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\ServiceProvider;
use Illuminate\Translation\Translator;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Http\Middleware\AuthorizeAction;
use SineMacula\Laravel\Authorization\Http\Middleware\RequirePermission;
use SineMacula\Laravel\Authorization\Http\Middleware\RequireRole;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\PermissionService;
use SineMacula\Laravel\Authorization\Services\PolicyService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Feature\Stubs\AuthenticatableIdentity;
use Tests\Feature\Stubs\CustomRoleMiddlewareDouble;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubPolicyStore;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\SwitchableSubjectResolver;
use Tests\TestCase;

/**
 * Feature coverage for the service provider's request and job lifetimes and its
 * language-file wiring.
 *
 * Every binding that holds state for one request or job is bound with
 * `scoped()`, so a queue worker running job after job in one container, and
 * Octane running request after request on cloned sandboxes, never see another
 * job's or request's tenant, cached grants or last decision. The package's
 * language lines load under the `authorization` namespace, publish under the
 * `authorization-lang` tag, and reach the manager through the translator it is
 * given.
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
#[CoversClass(TenantScope::class)]
#[CoversClass(ResolvedTenant::class)]
#[CoversClass(ResolutionCache::class)]
#[CoversClass(LastDecisionStore::class)]
#[CoversClass(AuthorizationManager::class)]
final class AuthorizationServiceProviderTest extends TestCase
{
    /**
     * Configure the switchable subject resolver, as an application configures
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
        $config->set('authorization.subject_resolver', SwitchableSubjectResolver::class);

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
        SwitchableSubjectResolver::$tenant = null;
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
            SubjectResolver::class,
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
     * The configured policy store is shared within a job and rebuilt for the
     * next one, so any state it keeps ends with the job.
     *
     * @return void
     */
    public function testConfiguredPolicyStoreIsRebuiltForEachJob(): void
    {
        $app = $this->application();

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);
        $config->set('authorization.policy_store', StubPolicyStore::class);

        (new AuthorizationServiceProvider($app))->register();

        $first = $app->make(PolicyStore::class);

        self::assertInstanceOf(StubPolicyStore::class, $first);
        self::assertSame($first, $app->make(PolicyStore::class));

        $this->startNextJob();

        $next = $app->make(PolicyStore::class);

        self::assertInstanceOf(StubPolicyStore::class, $next);
        self::assertNotSame($first, $next);
    }

    /**
     * A resolver contract the application binds itself, after the package
     * registered its defaults, survives the reset between jobs and is the one
     * the next job's manager is built with.
     *
     * @return void
     */
    public function testApplicationBoundResolversSurviveTheJobReset(): void
    {
        $app = $this->application();

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);
        $config->set('authorization.policy_store', StubPolicyStore::class);

        (new AuthorizationServiceProvider($app))->register();

        $bound = [
            SubjectResolver::class => new StubSubjectResolver,
            PolicyStore::class     => new StubPolicyStore,
            PolicyResolver::class  => new DefaultPolicyResolver,
        ];

        foreach ($bound as $contract => $instance) {
            $app->instance($contract, $instance);
        }

        $this->startNextJob();

        foreach ($bound as $contract => $instance) {
            self::assertSame($instance, $app->make($contract), "{$contract} bound by the application should survive the reset.");
        }

        $manager = $app->make(AuthorizationManager::class);

        self::assertSame($bound[SubjectResolver::class], (new \ReflectionProperty($manager, 'subjectResolver'))->getValue($manager));
        self::assertSame($bound[PolicyResolver::class], (new \ReflectionProperty($manager, 'policyResolver'))->getValue($manager));
    }

    /**
     * Rebinding the subject resolver or the held tenant empties the resolution
     * cache's memo, since its entries were resolved under the tenant they gave.
     *
     * @return void
     */
    public function testRebindingTheTenantEmptiesTheResolutionMemo(): void
    {
        $app         = $this->app;
        $resolutions = 0;
        $resolve     = static function () use (&$resolutions): Resolution {
            $resolutions++;

            return new Resolution(['posts:read']);
        };

        self::assertNotNull($app);

        $cache   = $app->make(ResolutionCache::class);
        $grantee = new Reference('user', 'user-1');

        $cache->rememberPermissions($grantee, $resolve);
        $cache->rememberPermissions($grantee, $resolve);
        $app->instance(SubjectResolver::class, new StubSubjectResolver(null));
        $cache->rememberPermissions($grantee, $resolve);
        $app->instance(ResolvedTenant::class, ResolvedTenant::from(new StubSubjectResolver(null)));
        $cache->rememberPermissions($grantee, $resolve);

        self::assertSame(3, $resolutions);
    }

    /**
     * Registering the provider again resolves nothing, though the tenant
     * bindings it watches are already bound.
     *
     * @return void
     */
    public function testRegisteringAgainResolvesNothing(): void
    {
        $app = $this->app;

        self::assertNotNull($app);

        $app->forgetInstance(ResolvedTenant::class);
        $resolved = 0;

        $app->resolving(ResolvedTenant::class, static function () use (&$resolved): void {
            $resolved++;
        });

        (new AuthorizationServiceProvider($app))->register();

        self::assertSame(0, $resolved);
    }

    /**
     * Without a configured lifetime, entries live five minutes.
     *
     * @return void
     */
    public function testEntriesLiveFiveMinutesByDefault(): void
    {
        $app = $this->app;

        self::assertNotNull($app);

        config(['authorization.cache' => ['store' => null]]);
        $app->forgetInstance(ResolutionCache::class);

        Carbon::setTestNow('2026-07-01 12:00:00');

        $cache       = $app->make(ResolutionCache::class);
        $resolutions = 0;
        $resolve     = static function () use (&$resolutions): Resolution {
            $resolutions++;

            return new Resolution(['posts:read']);
        };

        $cache->rememberPermissions(new Reference('user', 'user-1'), $resolve);

        Carbon::setTestNow('2026-07-01 12:04:59');
        $cache->rememberPermissions(new Reference('user', 'user-1'), $resolve);

        Carbon::setTestNow('2026-07-01 12:05:00');
        $cache->rememberPermissions(new Reference('user', 'user-1'), $resolve);

        Carbon::setTestNow();

        self::assertSame(2, $resolutions);
    }

    /**
     * The management services are bound as singletons, since they hold no
     * state.
     *
     * @return void
     */
    public function testBindsTheManagementServicesAsSingletons(): void
    {
        foreach ([RoleService::class, PermissionService::class, PolicyService::class, GrantService::class] as $service) {
            self::assertTrue($this->app?->isShared($service), $service);
            self::assertInstanceOf($service, $this->app->make($service));
        }
    }

    /**
     * Every package command is registered in the console, the catalogue sync
     * and the prune included.
     *
     * @return void
     */
    public function testRegistersThePackageCommands(): void
    {
        $commands = \array_keys(Artisan::all());

        foreach (['list-roles', 'list-permissions', 'grant', 'revoke', 'why-can', 'migrate-spatie', 'sync', 'prune'] as $name) {
            self::assertContains("authorization:{$name}", $commands);
        }
    }

    /**
     * The configured subject resolver class is the one bound.
     *
     * @return void
     */
    public function testConfiguredSubjectResolverIsBound(): void
    {
        self::assertInstanceOf(SwitchableSubjectResolver::class, $this->application()->make(SubjectResolver::class));
    }

    /**
     * The shipped subject resolver has no tenant, so only platform-wide rows
     * are visible, whether or not a user is signed in.
     *
     * @return void
     */
    public function testTheShippedSubjectResolverSeesOnlyPlatformRows(): void
    {
        $app = $this->application();

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);
        $config->set('authorization.subject_resolver', AuthGuardSubjectResolver::class);

        (new AuthorizationServiceProvider($app))->register();

        self::assertInstanceOf(AuthGuardSubjectResolver::class, $app->make(SubjectResolver::class));

        Role::create(['name' => 'platform', 'guard' => 'web']);
        Role::create(['name' => 'owned', 'guard' => 'web', 'tenant_type' => 'tenant', 'tenant_id' => 't-1']);

        self::assertSame(['platform'], Role::query()->pluck('name')->all());

        $this->actingAs(AuthenticatableIdentity::create(['id' => 'user-signed-in']));
        $this->startNextJob();

        self::assertSame(['platform'], Role::query()->pluck('name')->all());
    }

    /**
     * Registering the provider binds the subject resolver and the resolved
     * tenant without building either, so no application resolver runs before
     * the first query.
     *
     * @return void
     */
    public function testRegisteringDoesNotResolveTheSubjectResolver(): void
    {
        $app = new Application(\dirname(__DIR__, 2));

        try {
            $app->instance('config', new ConfigRepositoryImplementation([
                'authorization' => ['subject_resolver' => SwitchableSubjectResolver::class],
            ]));

            (new AuthorizationServiceProvider($app))->register();

            self::assertTrue($app->bound(SubjectResolver::class));
            self::assertTrue($app->bound(ResolvedTenant::class));
            self::assertFalse($app->resolved(SubjectResolver::class));
            self::assertFalse($app->resolved(ResolvedTenant::class));
        } finally {
            Container::setInstance($this->application());
        }
    }

    /**
     * Rebinding the subject resolver after a tenant was resolved is seen by the
     * next query, which reads the new resolver's tenant.
     *
     * @return void
     */
    public function testRebindingTheSubjectResolverIsSeenByTheNextQuery(): void
    {
        [$tenantA, $tenantB] = $this->seedTwoTenants();

        $app = $this->application();

        SwitchableSubjectResolver::$tenant = $tenantA;

        self::assertSame(['a-editor', 'global', 'on-call'], $this->visibleRoleNames());

        $app->instance(SubjectResolver::class, new StubSubjectResolver(new \stdClass, $tenantB));

        self::assertSame(['b-editor', 'global', 'on-call'], $this->visibleRoleNames());
    }

    /**
     * A subject resolver the application binds itself keeps reporting its
     * tenant after the reset between jobs, and the tenant reaches the scope in
     * the next job.
     *
     * @return void
     */
    public function testApplicationBoundSubjectResolverKeepsItsTenantAcrossJobs(): void
    {
        [, $tenantB] = $this->seedTwoTenants();

        $resolver = new StubSubjectResolver(new \stdClass, $tenantB);
        $this->application()->instance(SubjectResolver::class, $resolver);

        self::assertSame(['b-editor', 'global', 'on-call'], $this->visibleRoleNames());

        $this->startNextJob();

        self::assertSame($resolver, $this->application()->make(SubjectResolver::class));
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
        SwitchableSubjectResolver::$tenant = $tenantA;

        self::assertSame(['a-editor', 'global', 'on-call'], $this->visibleRoleNames());
        self::assertSame(['a-editor', 'on-call'], $this->rolesOf($userId));

        Authorization::for($this->identity($userId))->evaluate('posts:read');

        self::assertNotNull(Authorization::lastDecision());

        // The temporary grant expires between the two jobs.
        Carbon::setTestNow('2026-07-01 12:10:00');

        // Job 2, for tenant B.
        $this->startNextJob();
        SwitchableSubjectResolver::$tenant = $tenantB;

        self::assertSame(['b-editor', 'global', 'on-call'], $this->visibleRoleNames());
        self::assertSame(['b-editor'], $this->rolesOf($userId));
        self::assertNull(Authorization::lastDecision());

        // Job 3, with no tenant: platform rows only.
        $this->startNextJob();
        SwitchableSubjectResolver::$tenant = null;

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

        SwitchableSubjectResolver::$tenant = $tenantA;

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
            SwitchableSubjectResolver::$tenant = $tenantA;

            Authorization::for($this->identity($userId))->evaluate('posts:read');

            return [$this->visibleRoleNames(), $this->rolesOf($userId), Authorization::lastDecision()];
        });

        self::assertSame(['a-editor', 'global', 'on-call'], $first[0]);
        self::assertSame(['a-editor', 'on-call'], $first[1]);
        self::assertNotNull($first[2]);

        $second = $this->inSandbox($base, function () use ($tenantB, $userId): array {
            SwitchableSubjectResolver::$tenant = $tenantB;

            return [$this->visibleRoleNames(), $this->rolesOf($userId), Authorization::lastDecision()];
        });

        self::assertSame(['b-editor', 'global', 'on-call'], $second[0]);
        self::assertSame(['b-editor', 'on-call'], $second[1]);
        self::assertNull($second[2]);
    }

    /**
     * The shipped English lines load under the `authorization` namespace.
     *
     * @return void
     */
    public function testLoadsTheLanguageLinesUnderThePackageNamespace(): void
    {
        self::assertSame('This action is unauthorized.', $this->translator()->get('authorization::authorization.denied'));
    }

    /**
     * The `authorization-lang` tag publishes the shipped `lang` directory into
     * the application's `lang/vendor/authorization` directory.
     *
     * @return void
     */
    public function testLangTagPublishesTheLanguageFiles(): void
    {
        $paths = ServiceProvider::pathsToPublish(AuthorizationServiceProvider::class, 'authorization-lang');

        self::assertCount(1, $paths);

        $source = (string) \array_key_first($paths);

        self::assertSame(\realpath(__DIR__ . '/../../lang'), \realpath($source));
        self::assertSame($this->application()->langPath('vendor/authorization'), $paths[$source]);
    }

    /**
     * The manager words a denial through the application's translator, in its
     * current locale.
     *
     * @return void
     */
    public function testManagerTranslatesTheDenialInTheCurrentLocale(): void
    {
        $translator = $this->translator();
        $translator->addLines(['authorization.denied' => 'Action non autorisée.'], 'fr', 'authorization');
        $translator->setLocale('fr');

        try {
            $this->application()->make(AuthorizationManager::class)->authorize('posts:create');
            self::fail('Expected AuthorizationException.');
        } catch (AuthorizationException $exception) {
            self::assertSame('Action non autorisée.', $exception->getMessage());
        }
    }

    /**
     * The shipped language file has a line for the missing-role denial.
     *
     * @return void
     */
    public function testLoadsTheRoleRequiredLine(): void
    {
        self::assertSame('This action requires a role you do not have.', $this->translator()->get(AuthorizationException::ROLE_REQUIRED_KEY));
    }

    /**
     * The provider registers the `role`, `permission` and `authorize` route
     * middleware aliases.
     *
     * @return void
     */
    public function testRegistersTheRouteMiddlewareAliases(): void
    {
        $middleware = $this->router()->getMiddleware();

        self::assertSame(RequireRole::class, $middleware['role'] ?? null);
        self::assertSame(RequirePermission::class, $middleware['permission'] ?? null);
        self::assertSame(AuthorizeAction::class, $middleware['authorize'] ?? null);
    }

    /**
     * The `authorize` middleware is placed once, right after
     * `SubstituteBindings`, in the router's middleware priority, however often
     * the provider boots.
     *
     * @return void
     */
    public function testPlacesTheAuthorizeMiddlewareRightAfterBindingSubstitution(): void
    {
        (new AuthorizationServiceProvider($this->application()))->boot();

        $priority = $this->router()->middlewarePriority;
        $bindings = \array_search(SubstituteBindings::class, $priority, true);

        self::assertIsInt($bindings);
        self::assertSame(AuthorizeAction::class, $priority[$bindings + 1] ?? null);
        self::assertCount(1, \array_keys($priority, AuthorizeAction::class, true));
    }

    /**
     * Without an HTTP kernel there is no priority to extend, and the provider
     * still registers the aliases.
     *
     * @return void
     */
    public function testBootsWithoutAnHttpKernel(): void
    {
        $router = new Router(new Dispatcher($this->application()), $this->application());

        $this->application()->offsetUnset(HttpKernelContract::class);
        $this->application()->instance('router', $router);

        (new AuthorizationServiceProvider($this->application()))->boot();

        self::assertSame([], $router->middlewarePriority);
        self::assertSame(AuthorizeAction::class, $router->getMiddleware()['authorize'] ?? null);
    }

    /**
     * An alias the application has already taken keeps its middleware, while
     * the free ones are still registered.
     *
     * @return void
     */
    public function testKeepsTheRouteMiddlewareAliasesTheApplicationTook(): void
    {
        foreach (['role', 'permission', 'authorize'] as $taken) {
            $router = new Router(new Dispatcher($this->application()), $this->application());
            $router->aliasMiddleware($taken, CustomRoleMiddlewareDouble::class);

            $this->application()->instance('router', $router);

            (new AuthorizationServiceProvider($this->application()))->boot();

            $expected = [
                'role'       => RequireRole::class,
                'permission' => RequirePermission::class,
                'authorize'  => AuthorizeAction::class,
            ];

            self::assertSame([$taken => CustomRoleMiddlewareDouble::class] + $expected, $router->getMiddleware(), "The {$taken} alias was not kept.");
        }
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

        Role::create(['name' => 'global', 'guard' => 'web']);
        $onCall  = Role::create(['name' => 'on-call', 'guard' => 'web']);
        $aEditor = Role::create(['name' => 'a-editor', 'guard' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => 'tenant-a']);
        $bEditor = Role::create(['name' => 'b-editor', 'guard' => 'web', 'tenant_type' => $tenantB->getMorphClass(), 'tenant_id' => 'tenant-b']);

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
     * Resolve the application's translator.
     *
     * @return \Illuminate\Translation\Translator
     */
    private function translator(): Translator
    {
        /** @var \Illuminate\Translation\Translator */
        return $this->application()->make('translator');
    }

    /**
     * Return the application's router.
     *
     * @return \Illuminate\Routing\Router
     */
    private function router(): Router
    {
        /** @var \Illuminate\Routing\Router */
        return $this->application()->make('router');
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
