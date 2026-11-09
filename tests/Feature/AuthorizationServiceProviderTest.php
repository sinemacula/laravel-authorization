<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepositoryImplementation;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Http\Kernel as HttpKernelContract;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
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
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Context\ClockEnvironmentContext;
use SineMacula\Laravel\Authorization\Context\DeclaredContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Context\GuardAuthenticationContext;
use SineMacula\Laravel\Authorization\Context\RoutedRequestContext;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\EnvironmentContext;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\RequestContext;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Hooks\GrantHooks;
use SineMacula\Laravel\Authorization\Http\Middleware\AuthorizeAction;
use SineMacula\Laravel\Authorization\Http\Middleware\RequirePermission;
use SineMacula\Laravel\Authorization\Http\Middleware\RequireRole;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Preview\Previewing;
use SineMacula\Laravel\Authorization\Query\SchemaInspector;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Registrars\QueryScopeRegistrar;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\DeclaredResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Resolvers\GuardUserIdentityDirectory;
use SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy;
use SineMacula\Laravel\Authorization\Resolvers\ReferenceSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;
use SineMacula\Laravel\Authorization\Reviews\AccessReview;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\ApplicationAccess;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantScopeQuery;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\GuardrailService;
use SineMacula\Laravel\Authorization\Services\PermissionService;
use SineMacula\Laravel\Authorization\Services\PolicyService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\DeclaredAbilities;
use SineMacula\Laravel\Authorization\Support\DeclaredActionCatalogue;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Support\SessionScopes;
use Tests\Feature\Stubs\AuthenticatableIdentity;
use Tests\Feature\Stubs\CatalogueReadingProvider;
use Tests\Feature\Stubs\CustomRoleMiddlewareDouble;
use Tests\Feature\Stubs\FixedConsoleSubjectResolver;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\InjectedRequirementChecker;
use Tests\Feature\Stubs\LateAuthenticationContextProvider;
use Tests\Feature\Stubs\PermissiveActionCatalogue;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubPolicyStore;
use Tests\Feature\Stubs\StubSessionPolicySource;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Feature\Stubs\SwitchableSubjectResolver;
use Tests\Fixtures\GrantHooks\RecordingGrantHook;
use Tests\Fixtures\GrantHooks\RefusingGrantHook;
use Tests\Fixtures\GrantScope\ListedIdentityDirectory;
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
        $app = $this->application();
        $app->forgetExtenders(ActionCatalogue::class);

        $abstracts = [
            ActionCatalogue::class,
            SubjectResolver::class,
            TenantTree::class,
            IdentityDirectory::class,
            ResourceTenantResolver::class,
            AuthenticationRequirementChecker::class,
            SessionPolicySource::class,
            SessionScopes::class,
            ResolvedTenant::class,
            ResolutionCache::class,
            PolicyResolver::class,
            LastDecisionStore::class,
            PolicyEvaluator::class,
            AuthenticationContext::class,
            RequestContext::class,
            EnvironmentContext::class,
            CheckContextFactory::class,
            DeclaredAbilities::class,
            'authorization',
            AuthorizationManager::class,
            Previewing::class,
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
            SubjectResolver::class        => new StubSubjectResolver,
            PolicyStore::class            => new StubPolicyStore,
            PolicyResolver::class         => new DefaultPolicyResolver,
            ResourceTenantResolver::class => new FixedResourceTenantResolver,
        ];

        foreach ($bound as $contract => $instance) {
            $app->instance($contract, $instance);
        }

        $this->startNextJob();

        foreach ($bound as $contract => $instance) {
            self::assertSame($instance, $app->make($contract), "{$contract} bound by the application should survive the reset.");
        }

        $manager  = $app->make(AuthorizationManager::class);
        $pipeline = (new \ReflectionProperty($manager, 'pipeline'))->getValue($manager);

        self::assertInstanceOf(DecisionPipeline::class, $pipeline);
        self::assertSame($bound[SubjectResolver::class], (new \ReflectionProperty($manager, 'subjectResolver'))->getValue($manager));
        self::assertSame($bound[PolicyResolver::class], (new \ReflectionProperty($pipeline, 'policyResolver'))->getValue($pipeline));
    }

    /**
     * Provide every seam, the context key catalogue included, with each way of
     * binding it.
     *
     * @return iterable<string, array{class-string, string}>
     */
    public static function seamBindingProvider(): iterable
    {
        $seams = [...\array_column(\iterator_to_array(self::seamProvider()), 0), ContextKeyCatalogue::class];

        foreach ($seams as $seam) {
            foreach (['bind', 'singleton', 'scoped', 'instance'] as $method) {
                yield "{$seam} by {$method}" => [$seam, $method];
            }
        }
    }

    /**
     * A binding a sibling package or the application makes before the package
     * registers stands, however it was made (N103).
     *
     * @param  class-string  $contract
     * @param  string  $method
     * @return void
     */
    #[DataProvider('seamBindingProvider')]
    public function testABindingMadeBeforeRegistrationStands(string $contract, string $method): void
    {
        $app   = $this->unboundSeam($contract);
        $bound = self::createStub($contract);

        self::bindBy($app, $method, $contract, $bound);

        (new AuthorizationServiceProvider($app))->register();

        self::assertSame($bound, $app->make($contract));
    }

    /**
     * A binding made after the package registered replaces its default, however
     * it was made.
     *
     * @param  class-string  $contract
     * @param  string  $method
     * @return void
     */
    #[DataProvider('seamBindingProvider')]
    public function testABindingMadeAfterRegistrationReplacesTheDefault(string $contract, string $method): void
    {
        $app   = $this->unboundSeam($contract);
        $bound = self::createStub($contract);

        (new AuthorizationServiceProvider($app))->register();

        self::bindBy($app, $method, $contract, $bound);

        self::assertSame($bound, $app->make($contract));
    }

    /**
     * Provide every contract the package binds as a default an application or
     * sibling package may own, by its scoped default.
     *
     * @return iterable<string, array{class-string}>
     */
    public static function seamProvider(): iterable
    {
        $seams = [
            SubjectResolver::class,
            TenantTree::class,
            IdentityDirectory::class,
            GrantHook::class,
            ConsoleSubjectResolver::class,
            ResourceTenantResolver::class,
            PolicyStore::class,
            PolicyResolver::class,
            ActionCatalogue::class,
            AuthenticationRequirementChecker::class,
            SessionPolicySource::class,
            AuthenticationContext::class,
            RequestContext::class,
            EnvironmentContext::class,
        ];

        foreach ($seams as $seam) {
            yield $seam => [$seam];
        }
    }

    /**
     * A seam nothing else binds resolves the package's default, through the
     * package-owned key that holds it.
     *
     * @param  class-string  $contract
     * @return void
     */
    #[DataProvider('seamProvider')]
    public function testAnUnboundSeamGetsTheDefault(string $contract): void
    {
        $app = $this->unboundSeam($contract);

        (new AuthorizationServiceProvider($app))->register();

        $resolved = $app->make($contract);

        self::assertInstanceOf($contract, $resolved);
        self::assertSame($app->make("authorization.default:{$contract}"), $resolved);
    }

    /**
     * The default stays reachable under the package-owned key when a binding
     * made before registration stands on the contract.
     *
     * @param  class-string  $contract
     * @return void
     */
    #[DataProvider('seamProvider')]
    public function testTheDefaultStaysReachableBesideABindingThatStands(string $contract): void
    {
        $app   = $this->unboundSeam($contract);
        $bound = self::createStub($contract);

        $app->instance($contract, $bound);

        (new AuthorizationServiceProvider($app))->register();

        self::assertSame($bound, $app->make($contract));
        self::assertInstanceOf($contract, $app->make("authorization.default:{$contract}"));
        self::assertNotSame($bound, $app->make("authorization.default:{$contract}"));
    }

    /**
     * With nothing else bound, the context key catalogue is the package's
     * declared catalogue.
     *
     * @return void
     */
    public function testAnUnboundContextKeyCatalogueGetsTheDeclaredOne(): void
    {
        $app = $this->unboundSeam(ContextKeyCatalogue::class);

        (new AuthorizationServiceProvider($app))->register();

        self::assertInstanceOf(DeclaredContextKeyCatalogue::class, $app->make(ContextKeyCatalogue::class));
    }

    /**
     * A subject resolver a sibling package bound before the package registered
     * is not resolved while it registers, and rebinding it once it has been
     * resolved still empties the resolution cache's memo.
     *
     * @return void
     */
    public function testRebindingASeamBoundBeforeRegistrationEmptiesTheMemo(): void
    {
        $app = new Application(\dirname(__DIR__, 2));

        try {
            $app->instance('config', new ConfigRepositoryImplementation(['authorization' => []]));
            $app->bind(SubjectResolver::class, static fn (): StubSubjectResolver => new StubSubjectResolver(null));

            (new AuthorizationServiceProvider($app))->register();

            self::assertFalse($app->resolved(SubjectResolver::class));

            $resolutions = 0;
            $resolve     = static function () use (&$resolutions): Resolution {
                $resolutions++;

                return new Resolution(['posts:read']);
            };

            $cache   = $app->make(ResolutionCache::class);
            $grantee = new Reference('user', 'user-1');

            $app->make(SubjectResolver::class);
            $cache->rememberPermissions($grantee, $resolve);
            $cache->rememberPermissions($grantee, $resolve);
            $app->instance(SubjectResolver::class, new StubSubjectResolver(null));
            $cache->rememberPermissions($grantee, $resolve);

            self::assertSame(2, $resolutions);
        } finally {
            Container::setInstance($this->application());
        }
    }

    /**
     * The authentication context a provider registering after the package binds
     * is the one whose namespaces and assurance keys the catalogue reads, even
     * when another provider resolved the catalogue before it registered (N104).
     *
     * @return void
     */
    public function testTheCatalogueReadsTheContextOfAProviderRegisteringLater(): void
    {
        $app = new Application(\dirname(__DIR__, 2));

        try {
            $app->instance('config', new ConfigRepositoryImplementation(['authorization' => ['context' => ['keys' => [
                'mfa' => ['level' => 'number'],
                'sso' => ['provider_name' => 'string', 'tenant' => 'string'],
            ]]]]));

            $app->register(new AuthorizationServiceProvider($app));
            $app->register(new CatalogueReadingProvider($app));
            $app->register(new LateAuthenticationContextProvider($app, ['level', 'provider_*']));

            $catalogue = $app->make(ContextKeyCatalogue::class);

            self::assertFalse($catalogue->permits('mfa.level', 'eq'));
            self::assertFalse($catalogue->permits('sso.provider_name', 'eq'));
            self::assertTrue($catalogue->permits('sso.tenant', 'eq'));
            self::assertTrue($catalogue->permits('mfa.enrolled', 'bool'));
        } finally {
            Container::setInstance($this->application());
        }
    }

    /**
     * The boot-time validation reads the authentication context a provider
     * registering after the package binds, so its malformed assurance keys are
     * refused at boot (N104).
     *
     * @return void
     */
    public function testBootValidatesTheContextOfAProviderRegisteringLater(): void
    {
        $app = new Application(\dirname(__DIR__, 2));

        try {
            $app->instance('config', new ConfigRepositoryImplementation(['authorization' => []]));

            $app->register(new AuthorizationServiceProvider($app));
            $app->register(new LateAuthenticationContextProvider($app, ['provider.*']));

            $this->expectException(InvalidAuthorizationConfigException::class);
            $this->expectExceptionMessage('declares the assurance key \'provider.*\'');

            $app->boot();
        } finally {
            Container::setInstance($this->application());
        }
    }

    /**
     * Rebinding the subject resolver, the held tenant or the tenant tree
     * empties the resolution cache's memo, since its entries were resolved
     * under the tenant and ancestors they gave.
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
        $app->instance(TenantTree::class, new StubTenantTree);
        $cache->rememberPermissions($grantee, $resolve);

        self::assertSame(4, $resolutions);
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
        $services = [
            RoleService::class,
            PermissionService::class,
            PolicyService::class,
            GrantService::class,
            ResourcePolicyService::class,
            BoundaryService::class,
            GuardrailService::class,
            ApplicationAccess::class,
            GrantScopeQuery::class,
            AccessReview::class,
        ];

        foreach ($services as $service) {
            self::assertTrue($this->app?->isShared($service), $service);
            self::assertInstanceOf($service, $this->app->make($service));
        }
    }

    /**
     * Every package command is registered in the console, the catalogue sync,
     * the prune, the policy validation, the configuration check and the
     * explanation included, and `authorization:why-can`, which
     * `authorization:why` replaced, no longer is.
     *
     * @return void
     */
    public function testRegistersThePackageCommands(): void
    {
        $commands = \array_keys(Artisan::all());

        foreach (['list-roles', 'list-permissions', 'grant', 'revoke', 'why', 'migrate-spatie', 'sync', 'prune', 'policy:validate', 'check'] as $name) {
            self::assertContains("authorization:{$name}", $commands);
        }

        self::assertNotContains('authorization:why-can', $commands);
    }

    /**
     * The console subject resolver defaults to `ReferenceSubjectResolver`, and
     * one the application binds on the contract replaces it and survives the
     * reset between jobs.
     *
     * @return void
     */
    public function testBindsTheConsoleSubjectResolver(): void
    {
        $app = $this->application();

        self::assertInstanceOf(ReferenceSubjectResolver::class, $app->make(ConsoleSubjectResolver::class));

        $bound = new FixedConsoleSubjectResolver(new Subject(new \stdClass));
        $app->instance(ConsoleSubjectResolver::class, $bound);

        $this->startNextJob();

        self::assertSame($bound, $app->make(ConsoleSubjectResolver::class));
    }

    /**
     * The action catalogue a policy document is checked against defaults to the
     * permissions the code declares, and one the application binds itself
     * replaces it and survives the reset between jobs.
     *
     * @return void
     */
    public function testBindsTheDeclaredActionCatalogue(): void
    {
        $app = $this->application();
        $app->forgetExtenders(ActionCatalogue::class);

        self::assertInstanceOf(DeclaredActionCatalogue::class, $app->make(ActionCatalogue::class));

        $bound = new PermissiveActionCatalogue;
        $app->instance(ActionCatalogue::class, $bound);

        $this->startNextJob();

        self::assertSame($bound, $app->make(ActionCatalogue::class));
    }

    /**
     * The context key catalogue declares the package's keys and those of
     * `authorization.context.keys`, and is one per application: a key a service
     * provider registers on it is kept across the reset between jobs.
     *
     * @return void
     */
    public function testBindsOneContextKeyCataloguePerApplication(): void
    {
        $app = $this->application();
        $app->forgetExtenders(ContextKeyCatalogue::class);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);
        $config->set('authorization.context.keys', ['input' => ['post.status' => 'string']]);

        $catalogue = $app->make(ContextKeyCatalogue::class);

        self::assertInstanceOf(DeclaredContextKeyCatalogue::class, $catalogue);
        self::assertTrue($catalogue->permits('input.post.status', 'eq'));
        self::assertTrue($catalogue->permits('request.ip', 'ip_in'));

        $catalogue->register('tenant', ['plan' => 'string']);

        $this->startNextJob();

        self::assertSame($catalogue, $app->make(ContextKeyCatalogue::class));
        self::assertTrue($app->make(ContextKeyCatalogue::class)->permits('tenant.plan'));
    }

    /**
     * The trusted context sources default to Laravel's guard, routed request
     * and clock, and the manager builds each check's context from them; one the
     * application binds itself replaces the default and survives the reset
     * between jobs.
     *
     * @return void
     */
    public function testBindsTheTrustedContextSources(): void
    {
        $app = $this->application();

        self::assertInstanceOf(GuardAuthenticationContext::class, $app->make(AuthenticationContext::class));
        self::assertInstanceOf(RoutedRequestContext::class, $app->make(RequestContext::class));
        self::assertInstanceOf(ClockEnvironmentContext::class, $app->make(EnvironmentContext::class));

        $environment = new class implements EnvironmentContext {
            /**
             * Return a region the check runs in.
             *
             * @return array<string, mixed>
             */
            #[\Override]
            public function values(): array
            {
                return ['region' => 'eu'];
            }
        };

        $app->instance(EnvironmentContext::class, $environment);

        $this->startNextJob();

        self::assertSame($environment, $app->make(EnvironmentContext::class));

        $policy = EvaluationPolicy::fromArray(['name' => 'eu-only', 'statements' => [
            ['effect' => 'allow', 'actions' => ['posts:create'], 'conditions' => ['eq' => ['environment.region' => 'eu']]],
        ]]);

        self::assertTrue(Authorization::for(new StubIdentity(['id' => 'eu']))->withPolicies([$policy])->can('posts:create', null, ['environment' => ['region' => 'us']]));
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
     * The flat tenant tree is bound by default, and the configured class in its
     * place.
     *
     * @return void
     */
    public function testConfiguredTenantTreeIsBound(): void
    {
        $app = $this->application();

        self::assertSame('web', $app->make(ResolvedTenant::class)->guard);

        $default = $app->make(TenantTree::class);

        self::assertInstanceOf(FlatTenantTree::class, $default);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);
        $config->set('authorization.tenant_tree', StubTenantTree::class);

        (new AuthorizationServiceProvider($app))->register();

        $configured = $app->make(TenantTree::class);

        self::assertInstanceOf(StubTenantTree::class, $configured);
    }

    /**
     * The identity directory that knows the shipped resolver's users is bound
     * by default, and the configured class in its place.
     *
     * @return void
     */
    public function testConfiguredIdentityDirectoryIsBound(): void
    {
        $app = $this->application();

        $default = $app->make(IdentityDirectory::class);

        self::assertInstanceOf(GuardUserIdentityDirectory::class, $default);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);
        $config->set('authorization.identity_directory', ListedIdentityDirectory::class);

        (new AuthorizationServiceProvider($app))->register();

        $configured = $app->make(IdentityDirectory::class);

        self::assertInstanceOf(ListedIdentityDirectory::class, $configured);
    }

    /**
     * The grant hook is the composite of the configured hooks, holding none by
     * default and each configured class in order once configured, rebuilt for
     * each job; a hook the application binds on the contract replaces it and is
     * kept.
     *
     * @return void
     */
    public function testTheConfiguredGrantHooksAreBound(): void
    {
        $app = $this->application();

        $default = $app->make(GrantHook::class);

        self::assertInstanceOf(GrantHooks::class, $default);
        self::assertTrue($default->isEmpty());
        self::assertSame($default, $app->make(GrantHook::class));

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);
        $config->set('authorization.grant_hooks', [RefusingGrantHook::class, RecordingGrantHook::class]);

        $app->forgetScopedInstances();

        $configured = $app->make(GrantHook::class);

        self::assertInstanceOf(GrantHooks::class, $configured);
        self::assertSame([RefusingGrantHook::class, RecordingGrantHook::class], \array_map(static fn (object $hook): string => $hook::class, $configured->hooks()));

        $own = new RecordingGrantHook;

        $app->instance(GrantHook::class, $own);
        $app->forgetScopedInstances();

        self::assertSame($own, $app->make(GrantHook::class));
    }

    /**
     * The declared resolver is bound around the resolver that knows no
     * resource's tenant by default, and around the configured class in its
     * place, which answers every model that declares no tenancy.
     *
     * @return void
     */
    public function testConfiguredResourceTenantResolverIsBound(): void
    {
        $app   = $this->application();
        $model = new StubIdentity;

        $default = $app->make(ResourceTenantResolver::class);

        self::assertInstanceOf(DeclaredResourceTenant::class, $default);
        self::assertNull($default->tenantOf($model));

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);
        $config->set('authorization.resource_tenant_resolver', FixedResourceTenantResolver::class);
        $app->instance(FixedResourceTenantResolver::class, $fixed = new FixedResourceTenantResolver(new Reference('fixed', '1')));

        (new AuthorizationServiceProvider($app))->register();

        $configured = $app->make(ResourceTenantResolver::class);

        self::assertInstanceOf(DeclaredResourceTenant::class, $configured);
        self::assertEquals(new Reference('fixed', '1'), $configured->tenantOf($model));
        self::assertSame([$model], $fixed->asked);
    }

    /**
     * Booting registers the `whereAuthorized()` builder macro, and the schema
     * inspector its scopes read through is bound once per request or job.
     *
     * @return void
     */
    public function testBootingRegistersTheQueryScopeMacro(): void
    {
        $app = $this->application();

        self::assertTrue(EloquentBuilder::hasGlobalMacro(QueryScopeRegistrar::MACRO));
        self::assertSame($app->make(SchemaInspector::class), $app->make(SchemaInspector::class));
        self::assertTrue($app->isShared(SchemaInspector::class));
    }

    /**
     * The checker that meets no requirement is bound by default, and the
     * configured class in its place; a checker the application binds itself
     * survives the reset between jobs.
     *
     * @return void
     */
    public function testConfiguredRequirementCheckerIsBound(): void
    {
        $app = $this->application();

        $default = $app->make(AuthenticationRequirementChecker::class);

        self::assertInstanceOf(RefusingRequirementChecker::class, $default);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);
        $config->set('authorization.requirement_checker', InjectedRequirementChecker::class);

        (new AuthorizationServiceProvider($app))->register();

        $configured = $app->make(AuthenticationRequirementChecker::class);

        self::assertInstanceOf(InjectedRequirementChecker::class, $configured);

        $bound = new RefusingRequirementChecker;

        $app->instance(AuthenticationRequirementChecker::class, $bound);

        $this->startNextJob();

        self::assertSame($bound, $app->make(AuthenticationRequirementChecker::class));
    }

    /**
     * The session policy source carrying no cap is bound by default, and the
     * configured class in its place; a source the application binds itself
     * survives the reset between jobs, and the manager caps its checks by the
     * source's scopes through the configured scope map.
     *
     * @return void
     */
    public function testConfiguredSessionPolicySourceIsBound(): void
    {
        $app = $this->application();

        $default = $app->make(SessionPolicySource::class);

        self::assertInstanceOf(NoSessionPolicy::class, $default);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);
        $config->set('authorization.session.source', StubSessionPolicySource::class);

        (new AuthorizationServiceProvider($app))->register();

        $configured = $app->make(SessionPolicySource::class);

        self::assertInstanceOf(StubSessionPolicySource::class, $configured);

        $bound = new StubSessionPolicySource(['editor']);

        $app->instance(SessionPolicySource::class, $bound);
        $config->set('authorization.session.scopes', ['editor' => ['posts:read']]);

        $this->startNextJob();

        self::assertSame($bound, $app->make(SessionPolicySource::class));
        self::assertSame(['posts:read'], $app->make(SessionScopes::class)->patternsFor(['editor']));

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $manager */
        $manager = $app->make(AuthorizationManager::class);
        $user    = new \stdClass;

        self::assertSame(DecisionReason::SESSION_POLICY, $manager->for($user)->check('posts:edit')->reason);
        self::assertSame(DecisionReason::NO_MATCH, $manager->for($user)->check('posts:read')->reason);
        self::assertCount(2, $bound->calls);
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

        Authorization::for($this->identity($userId))->check('posts:read');

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

            Authorization::for($this->identity($userId))->check('posts:read');

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
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
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
     * The shipped language file has a line for an unauthenticated request.
     *
     * @return void
     */
    public function testLoadsTheUnauthenticatedLine(): void
    {
        self::assertSame('Unauthenticated.', $this->translator()->get('authorization::authorization.unauthenticated'));
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
     * Bind the object on the contract the way the method names.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  string  $method
     * @param  class-string  $contract
     * @param  object  $bound
     * @return void
     */
    private static function bindBy(Application $app, string $method, string $contract, object $bound): void
    {
        $binders = [
            'bind'      => static fn () => $app->bind($contract, static fn (): object => $bound),
            'singleton' => static fn () => $app->singleton($contract, static fn (): object => $bound),
            'scoped'    => static fn () => $app->scoped($contract, static fn (): object => $bound),
            'instance'  => static fn () => $app->instance($contract, $bound),
        ];

        $binders[$method]();
    }

    /**
     * Return the booted application with nothing bound on the contract, the
     * test suite's extensions of it forgotten, and a policy store configured,
     * so the provider registers a default for every seam.
     *
     * @param  class-string  $contract
     * @return \Illuminate\Foundation\Application
     */
    private function unboundSeam(string $contract): Application
    {
        $app = $this->application();

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);
        $config->set('authorization.policy_store', StubPolicyStore::class);

        $app->forgetExtenders($contract);

        unset($app[$contract]);

        return $app;
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
