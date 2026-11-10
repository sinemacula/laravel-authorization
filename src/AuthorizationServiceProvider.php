<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization;

use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel as HttpKernelContract;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Foundation\Http\Kernel as HttpKernel;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Console\CheckConfigurationCommand;
use SineMacula\Laravel\Authorization\Console\GrantRoleCommand;
use SineMacula\Laravel\Authorization\Console\ListPermissionsCommand;
use SineMacula\Laravel\Authorization\Console\ListRolesCommand;
use SineMacula\Laravel\Authorization\Console\MigrateSpatieCommand;
use SineMacula\Laravel\Authorization\Console\PruneGrantsCommand;
use SineMacula\Laravel\Authorization\Console\ReviewCommand;
use SineMacula\Laravel\Authorization\Console\RevokeRoleCommand;
use SineMacula\Laravel\Authorization\Console\SyncPermissionsCommand;
use SineMacula\Laravel\Authorization\Console\UsageHeartbeatCommand;
use SineMacula\Laravel\Authorization\Console\UsagePruneCommand;
use SineMacula\Laravel\Authorization\Console\ValidatePolicyCommand;
use SineMacula\Laravel\Authorization\Console\WhyCommand;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Context\ContextBindings;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Http\Middleware\AuthorizeAction;
use SineMacula\Laravel\Authorization\Http\Middleware\RequirePermission;
use SineMacula\Laravel\Authorization\Http\Middleware\RequireRole;
use SineMacula\Laravel\Authorization\Preview\Previewing;
use SineMacula\Laravel\Authorization\Query\SchemaInspector;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Registrars\QueryScopeRegistrar;
use SineMacula\Laravel\Authorization\Registrars\SeamBindings;
use SineMacula\Laravel\Authorization\Registrars\UsageRegistrar;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\DeclaredResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Resolvers\GuardrailResolver;
use SineMacula\Laravel\Authorization\Resolvers\GuardUserIdentityDirectory;
use SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy;
use SineMacula\Laravel\Authorization\Resolvers\ReferenceSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\SessionCapResolver;
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
use SineMacula\Laravel\Authorization\Support\DeclaredActionCatalogue;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Support\SessionScopes;
use SineMacula\Laravel\Authorization\Usage\GrantUsageRecorder;
use SineMacula\Laravel\Authorization\Usage\UsageTracking;

/**
 * Service provider for the authorization package.
 *
 * Orchestrates the package's container bindings, config validation, publishing,
 * command registration, and boot-time wiring. Delegates the bulkier
 * responsibilities to dedicated registrars:
 *
 * - `GateRegistrar` — registers the single `Gate::before` hook through which
 *   the package answers every ability it declares, unless
 *   `authorization.gate.enabled` is false.
 * - `BladeDirectiveRegistrar` — wires the `@role` / `@permission` directive
 *   quartet and Spatie-compat aliases.
 * - `QueryScopeRegistrar` — registers the `whereAuthorized()` builder macro.
 * - `SeamBindings` — binds each contract an application may bind itself to the
 *   package's default, or to the class the configuration names, and runs the
 *   grant hooks the configuration lists before the bound hook.
 *
 * Every binding that holds state for one request or job (the resolvers, the
 * policy store, the resolved tenant, the resolution cache, the last decision,
 * the action catalogue, the context sources and the check context factory, what
 * its previews know, and the manager that holds them) is registered with
 * `scoped()`, so Laravel's queue worker drops it before each job and Octane
 * builds it afresh on each request's sandbox. They are scoped together: a
 * singleton holding a scoped instance would keep the old instance alive.
 *
 * The management services (roles, permissions, policies and grants), the
 * application access service and the grant scope query hold no state and are
 * bound as singletons.
 *
 * The context key catalogue is one per application, so the keys a service
 * provider registers on it are kept for every request and job.
 *
 * Grant usage tracking is wired by `UsageRegistrar`: the usage store, which an
 * application may bind itself, and the recorder, one per worker; while tracking
 * is on, the resolution cache keeps the routes behind each grantee's grants,
 * the manager notes those its everyday checks use, and the recorder flushes
 * them as each request, command or job ends. With tracking off none of this
 * runs.
 *
 * The contracts an application may bind itself (the subject resolver, the
 * tenant tree, the identity directory, the grant hook, the console subject
 * resolver, the resource tenant resolver, the policy store, the policy
 * resolver, the action catalogue, the authentication requirement checker, the
 * session policy source and the trusted context sources) resolve through a
 * package-owned key that holds the scoped default. Each contract is bound to
 * that key only when nothing is bound to it yet (N103), so a binding a sibling
 * package or the application made before this provider registers stands,
 * `instance()` included, and one made afterwards replaces the default. A
 * contract the application names a class other than the package's default for
 * in the configuration is bound to that key whatever was bound before (N106), a
 * deferred provider's binding included, so the application's configuration
 * replaces a sibling package's binding, and a binding made afterwards still
 * replaces it. The grant hook is the one exception: when the configuration
 * lists hooks, they run before whatever hook the contract resolves to, before
 * the package registers or after (N108). Either way a binding made outside the
 * package is not scoped by it, so an instance it binds survives the reset
 * between jobs. The context key catalogue is bound only when nothing is bound
 * to it yet. The closure a contract is bound to is declared by this provider,
 * as a sibling package that binds over the package's defaults tells them from
 * the application's own bindings by that closure's declaring class.
 *
 * Row-lifecycle behaviour for `Role` / `Permission` / `Policy` is attached via
 * the `#[ObservedBy]` attribute on each model; the service provider does not
 * touch model booting.
 *
 * Booting never queries or writes the database, so `config:cache`,
 * `route:cache` and `migrate` run before the package's tables exist, and a
 * configured permission provider is read at boot only to check the scope map,
 * when `authorization.session.scopes` names a scope. The permission catalogue
 * the enums and providers declare reaches the database only when
 * `authorization:sync` runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuthorizationServiceProvider extends ServiceProvider
{
    /**
     * Register container bindings.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/authorization.php', 'authorization');

        $this->registerConfiguredDefaults();
        $this->registerResourceTenantResolver();
        $this->registerResolvedTenant();
        $this->registerPolicyStore();
        $this->registerResolutionCache();
        $this->registerPolicyResolver();
        $this->registerLastDecisionStore();
        $this->registerPolicyEvaluator();
        $this->registerAuthorizationManager();
        $this->registerManagementServices();

        (new UsageRegistrar($this->app))->register();
    }

    /**
     * Boot the provider.
     *
     * The Gate hook is registered right after the configuration is validated,
     * before anything else, so it runs before every `Gate::before` callback an
     * application registers once the package has booted.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->validateConfig();

        (new GateRegistrar($this->app))->register();

        $this->loadTranslationsFrom(__DIR__ . '/../lang', 'authorization');
        $this->offerPublishing();
        $this->registerCommands();
        $this->registerRouteMiddleware();

        (new BladeDirectiveRegistrar($this->app))->register();
        (new QueryScopeRegistrar)->register();
        (new UsageRegistrar($this->app))->boot();
    }

    /**
     * Determine whether the contract is bound to the package's own default,
     * rather than to a binding an application or a sibling package made.
     *
     * A sibling that registers after the package uses this to replace the
     * package's default with its own adapter, while leaving standing a binding
     * the application made before the sibling registered. An unbound contract,
     * an instance and any binding the package did not make answer false.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  string  $contract
     * @return bool
     */
    public static function isPackageDefault(Container $container, string $contract): bool
    {
        $concrete = $container->getBindings()[$contract]['concrete'] ?? null;

        // An instance held over the default leaves the binding beneath it in
        // place, and Laravel offers no public way to tell, so the instances are
        // read in the container's own scope; the package's defaults are never
        // shared, so any instance held under the contract is someone's.
        $isHeld = \Closure::bind(static fn (Container $container): bool => isset($container->instances[$contract]), null, Container::class);

        return !$isHeld($container) && $concrete instanceof \Closure && (new \ReflectionFunction($concrete))->getClosureScopeClass()?->getName() === self::class;
    }

    /**
     * Fail fast on a malformed `authorization` config. Runs before any binding
     * is resolved so a typo surfaces as a clear typed exception rather than a
     * deep stack trace from the first `can()` call in production.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    protected function validateConfig(): void
    {
        /** @var array<string, mixed> $config */
        $config = (array) $this->app['config']->get('authorization', []);

        ConfigValidator::validate($config, $this->app);
    }

    /**
     * Register the package's Artisan commands when the application is running
     * in the console.
     *
     * @return void
     */
    protected function registerCommands(): void
    {
        if (!$this->app->runningInConsole()) {
            return;
        }

        $this->commands([
            ListRolesCommand::class,
            ListPermissionsCommand::class,
            GrantRoleCommand::class,
            RevokeRoleCommand::class,
            WhyCommand::class,
            ReviewCommand::class,
            MigrateSpatieCommand::class,
            SyncPermissionsCommand::class,
            PruneGrantsCommand::class,
            UsageHeartbeatCommand::class,
            UsagePruneCommand::class,
            ValidatePolicyCommand::class,
            CheckConfigurationCommand::class,
        ]);
    }

    /**
     * Bind the configured subject resolver, tenant tree and identity directory
     * as the defaults, the composite holding no hook as the grant hook, and
     * `ReferenceSubjectResolver` as the console subject resolver
     * `authorization:why` resolves its subject through, each scoped to the
     * request or job so any state it keeps does not reach the next one, and
     * each giving way to a binding a sibling package or the application makes
     * on its contract, before the package registers or after. A class the
     * configuration names in place of the package's default replaces a binding
     * made before the package registers instead (N106), and grant hooks it
     * lists run before whatever hook the contract resolves to (N108). Rebinding
     * the subject resolver or the tenant tree forgets the resolutions read
     * through it.
     *
     * @return void
     */
    protected function registerConfiguredDefaults(): void
    {
        $defaults = [
            SubjectResolver::class   => ['authorization.subject_resolver', AuthGuardSubjectResolver::class],
            TenantTree::class        => ['authorization.tenant_tree', FlatTenantTree::class],
            IdentityDirectory::class => ['authorization.identity_directory', GuardUserIdentityDirectory::class],
        ];

        $this->forgetResolutionsOnRebinding(SubjectResolver::class);
        $this->forgetResolutionsOnRebinding(TenantTree::class);

        $seams = $this->seams();

        foreach ($defaults as $contract => [$key, $default]) {
            $seams->bindConfigured($contract, $key, $default);
        }

        $seams->bindGrantHooks();
        $seams->bindDefault(ConsoleSubjectResolver::class, ReferenceSubjectResolver::class);
    }

    /**
     * Bind the configured resource tenant resolver as the default, scoped to
     * the request or job like the subject resolver, wrapped in the declared
     * resolver, which answers a model that declares its tenancy from its
     * declaration, as `whereAuthorized()` reads it, and passes every other to
     * the configured one. A class the configuration names in place of the
     * package's default replaces a binding made before the package registers
     * (N106).
     *
     * @return void
     */
    protected function registerResourceTenantResolver(): void
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver> $class */
        $class = $this->app['config']->get('authorization.resource_tenant_resolver', NoResourceTenant::class);

        $declared = static fn (Application $app): DeclaredResourceTenant => new DeclaredResourceTenant($app->make($class));

        $this->seams()->bindDefault(ResourceTenantResolver::class, $declared, $class !== NoResourceTenant::class);
    }

    /**
     * Bind the holder of the subject's tenant resolved for the current request
     * or job, which `TenantScope` reads. The holder remembers the resolver it
     * came from, so a resolver bound after the first query is still honoured.
     *
     * @return void
     */
    protected function registerResolvedTenant(): void
    {
        $this->forgetResolutionsOnRebinding(ResolvedTenant::class);

        $this->app->scoped(ResolvedTenant::class, static function (Application $app): ResolvedTenant {
            /** @var \SineMacula\Laravel\Authorization\Contracts\SubjectResolver $resolver */
            $resolver = $app->make(SubjectResolver::class);

            return ResolvedTenant::from($resolver, TenantScope::defaultGuard($app));
        });
    }

    /**
     * Bind the configured policy store, when there is one, scoped to the
     * request or job so any state it keeps does not reach the next one. The
     * package has no store of its own, so a configured one replaces a binding
     * made before the package registers (N106), and gives way to one made
     * afterwards.
     *
     * @return void
     */
    protected function registerPolicyStore(): void
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Contracts\PolicyStore>|null $class */
        $class = $this->app['config']->get('authorization.policy_store');

        if ($class === null) {
            return;
        }

        $this->seams()->bindDefault(PolicyStore::class, $class, true);
    }

    /**
     * Bind the resolution cache that memoises policy, permission, and role
     * lookups per-principal. Always on for in-memory memoisation, scoped to the
     * request or job; consults `authorization.cache.store` for optional
     * cross-request persistence.
     *
     * @return void
     */
    protected function registerResolutionCache(): void
    {
        $this->app->scoped(ResolutionCache::class, static function (Application $app): ResolutionCache {
            /** @var string|null $storeName */
            $storeName = $app['config']->get('authorization.cache.store');
            /** @var int $ttl */
            $ttl = (int) $app['config']->get('authorization.cache.ttl', 300);
            /** @var string $prefix */
            $prefix = (string) $app['config']->get('authorization.cache.prefix', 'authorization');

            $store = null;

            if ($storeName !== null && $app->bound('cache')) {
                /** @var \Illuminate\Cache\CacheManager $manager */
                $manager = $app->make('cache');
                $store   = $manager->store($storeName);
            }

            return new ResolutionCache(store: $store, ttl: $ttl, prefix: $prefix, isTrackingUsage: UsageTracking::isEnabled());
        });
    }

    /**
     * Bind the policy resolver — the internal policy-gathering seam the manager
     * consults on every evaluation. The default implementation unions an
     * optional `PolicyStore`, asked on every check, with the principal's own
     * attached policies, which the identity reads through the resolution cache.
     * Bound as the default, scoped to the request or job.
     *
     * @return void
     */
    protected function registerPolicyResolver(): void
    {
        $this->seams()->bindDefault(PolicyResolver::class, static fn (Application $app): PolicyResolver => new DefaultPolicyResolver(
            store: $app->bound(PolicyStore::class) ? $app->make(PolicyStore::class) : null,
        ));
    }

    /**
     * Bind the single-slot store that holds the most recent evaluation result
     * of the current request or job across every scoped clone of the manager.
     *
     * @return void
     */
    protected function registerLastDecisionStore(): void
    {
        $this->app->scoped(LastDecisionStore::class);
    }

    /**
     * Bind the policy evaluator and what a policy is checked against and reads.
     *
     * The action catalogue a policy document's action patterns are checked
     * against when it is written is by default the permissions the code
     * declares, read once per request or job. The context key catalogue its
     * condition keys and `${…}` references are checked against is one per
     * application, so the keys a service provider registers on it stay
     * registered across requests and jobs; it declares the package's keys and
     * those of `authorization.context.keys`. The trusted context sources
     * (authentication, request and environment) and the check context factory
     * that holds them with the sources of `authorization.context.sources` are
     * built per request or job, and so are the authentication requirement
     * checker `authorization.requirement_checker` names, the session policy
     * source `authorization.session.source` names and the scope map of
     * `authorization.session.scopes`. Each contract is bound as a default an
     * application may replace, the checker and the session policy source over a
     * binding made before the package registers when the configuration names a
     * class other than the package's default (N106), and the context key
     * catalogue only when nothing is bound to it yet. The catalogue reads the
     * authentication context's namespaces and assurance keys at its first use,
     * never here, so a context a later provider binds is the one it reads.
     *
     * @return void
     */
    protected function registerPolicyEvaluator(): void
    {
        $this->app->scoped(PolicyEvaluator::class);
        $this->app->scoped(SessionScopes::class, static fn (Application $app): SessionScopes => SessionScopes::fromConfig($app['config']->get('authorization.session.scopes', [])));

        $seams = $this->seams();

        $seams->bindConfigured(AuthenticationRequirementChecker::class, 'authorization.requirement_checker', RefusingRequirementChecker::class);
        $seams->bindConfigured(SessionPolicySource::class, 'authorization.session.source', NoSessionPolicy::class);

        foreach ([ActionCatalogue::class => DeclaredActionCatalogue::class, ...ContextBindings::DEFAULTS] as $contract => $concrete) {
            $seams->bindDefault($contract, $concrete);
        }

        $this->app->singletonIf(ContextKeyCatalogue::class, ContextBindings::catalogue(...));
        $this->app->scoped(CheckContextFactory::class, ContextBindings::factory(...));
    }

    /**
     * Bind the authorization manager, scoped to the request or job together
     * with the resolvers and stores it holds, what its previews know of the
     * request or job, and the schema inspector its query scopes read through.
     *
     * @return void
     */
    protected function registerAuthorizationManager(): void
    {
        $this->app->scoped('authorization', static fn (Application $app): AuthorizationManager => new AuthorizationManager(
            evaluator: $app->make(PolicyEvaluator::class),
            subjectResolver: $app->make(SubjectResolver::class),
            policyResolver: $app->make(PolicyResolver::class),
            lastDecisionStore: $app->make(LastDecisionStore::class),
            events: $app->bound(Dispatcher::class) ? $app->make(Dispatcher::class) : null,
            translator: $app->bound(Translator::class) ? $app->make(Translator::class) : null,
            contexts: $app->make(CheckContextFactory::class),
            resourcePolicies: new ResourcePolicyResolver,
            guardrails: new GuardrailResolver,
            sessionCaps: new SessionCapResolver($app->make(SessionPolicySource::class), $app->make(SessionScopes::class)),
            usage: UsageTracking::isEnabled() ? $app->make(GrantUsageRecorder::class) : null,
        ));

        $this->app->alias('authorization', AuthorizationManager::class);

        // Whether a preview is being evaluated, and which subjects its previews
        // are about, once a request or job.
        $this->app->scoped(Previewing::class);

        // What `whereAuthorized()` reads of each table and connection, once a
        // request or job.
        $this->app->scoped(SchemaInspector::class);
    }

    /**
     * Register the `role`, `permission` and `authorize` route-middleware
     * aliases.
     *
     * The aliases only light up when the `router` binding is available
     * (Laravel's default HTTP kernel), so console-only applications that do not
     * resolve the router never pay the registration cost. Existing aliases on
     * the same keys are respected — a consumer that has already wired their own
     * `role`, `permission` or `authorize` middleware keeps theirs untouched.
     *
     * `AuthorizeAction` is also placed right after `SubstituteBindings` in the
     * middleware priority, as Laravel places its own `can` middleware, so it
     * decides on the bound model however the route orders its middleware.
     *
     * @return void
     */
    protected function registerRouteMiddleware(): void
    {
        if (!$this->app->bound('router')) {
            return;
        }

        /** @var \Illuminate\Routing\Router $router */
        $router = $this->app->make('router');

        $aliases = [
            'role'       => RequireRole::class,
            'permission' => RequirePermission::class,
            'authorize'  => AuthorizeAction::class,
        ];

        foreach (\array_diff_key($aliases, $router->getMiddleware()) as $alias => $middleware) {
            $router->aliasMiddleware($alias, $middleware);
        }

        $this->prioritiseAuthorizeAction();
    }

    /**
     * Place `AuthorizeAction` right after `SubstituteBindings` in the HTTP
     * kernel's middleware priority, which the kernel copies to the router.
     *
     * Without Laravel's HTTP kernel there is no priority to extend.
     *
     * @return void
     */
    protected function prioritiseAuthorizeAction(): void
    {
        $kernel = $this->app->bound(HttpKernelContract::class) ? $this->app->make(HttpKernelContract::class) : null;

        if (!$kernel instanceof HttpKernel) {
            return;
        }

        $kernel->addToMiddlewarePriorityAfter(SubstituteBindings::class, AuthorizeAction::class);
    }

    /**
     * Offer config, migration and language-file publishing.
     *
     * @return void
     */
    protected function offerPublishing(): void
    {
        if (!$this->app->runningInConsole()) {
            return;
        }

        $this->publishes(
            [__DIR__ . '/../config/authorization.php' => config_path('authorization.php')],
            'authorization-config',
        );

        $this->publishes(
            [__DIR__ . '/../database/migrations' => database_path('migrations')],
            'authorization-migrations',
        );

        $this->publishes(
            [__DIR__ . '/../lang' => $this->app->langPath('vendor/authorization')],
            'authorization-lang',
        );
    }

    /**
     * Bind the management services that own every write of a role, permission,
     * policy, grant, resource policy attachment, permission boundary or
     * guardrail, and the services that answer factual questions about grants:
     * application access, the grant scope query and the access reviews. They
     * hold no state, so each is a singleton.
     *
     * @return void
     */
    private function registerManagementServices(): void
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
            $this->app->singleton($service);
        }
    }

    /**
     * Empty the resolution cache's memo whenever the abstract is rebound, as
     * replacing the subject resolver or the held tenant changes the tenant the
     * memo's entries were resolved under.
     *
     * `rebinding()` resolves an abstract that is already bound, and nothing may
     * be resolved while the provider registers. An abstract not bound yet is
     * watched at once, on the application, and every Octane sandbox cloned from
     * it keeps the watch. One already bound, by a sibling package or the
     * application before the package registered, `instance()` included, is
     * watched from its first resolution in each container that resolves it,
     * whether that binding stands or the class the configuration names replaced
     * it (N106), the earliest a rebinding could change anything that
     * container's memo holds: the watch is added before the resolution, on the
     * container resolving it, so a sandbox is watched in its own right and
     * nothing is built on the application it was cloned from. Only the abstract
     * itself starts the watch, never a class that implements it, and only when
     * resolved without parameters, since starting it resolves the abstract
     * again without them.
     *
     * The memo emptied is the one of the container rebinding the abstract, and
     * only once that container has resolved it, so a rebinding never builds a
     * memo.
     *
     * @param  string  $abstract
     * @return void
     */
    private function forgetResolutionsOnRebinding(string $abstract): void
    {
        $forget = static function (Container $container): void {
            if (!$container->resolved(ResolutionCache::class)) {
                return;
            }

            $container->make(ResolutionCache::class)->tenantChanged();
        };

        if (!$this->app->bound($abstract)) {
            // @phpstan-ignore staticMethod.dynamicCall
            $this->app->rebinding($abstract, $forget);

            return;
        }

        /** @var \WeakMap<\Illuminate\Container\Container, true> $watched */
        $watched = new \WeakMap;

        $this->app->beforeResolving($abstract, static function (string $resolving, array $parameters, Container $container) use ($abstract, $forget, $watched): void {
            if ($resolving !== $abstract || $parameters !== [] || isset($watched[$container])) {
                return;
            }

            $watched[$container] = true;

            $container->rebinding($abstract, $forget);
        });
    }

    /**
     * Return the registrar of the seams an application may bind itself, handed
     * the closure that builds the closure each contract is bound to.
     *
     * The provider declares that closure, so a sibling package that reads the
     * binding table tells the package's default from the application's own
     * binding by its declaring class, this provider, and replaces only the
     * default.
     *
     * @return \SineMacula\Laravel\Authorization\Registrars\SeamBindings
     */
    private function seams(): SeamBindings
    {
        return new SeamBindings($this->app, static fn (string $key): \Closure => static fn (Application $app): mixed => $app->make($key));
    }
}
