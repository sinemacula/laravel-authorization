<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel as HttpKernelContract;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Foundation\Http\Kernel as HttpKernel;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Console\GrantRoleCommand;
use SineMacula\Laravel\Authorization\Console\ListPermissionsCommand;
use SineMacula\Laravel\Authorization\Console\ListRolesCommand;
use SineMacula\Laravel\Authorization\Console\MigrateSpatieCommand;
use SineMacula\Laravel\Authorization\Console\PruneGrantsCommand;
use SineMacula\Laravel\Authorization\Console\RevokeRoleCommand;
use SineMacula\Laravel\Authorization\Console\SyncPermissionsCommand;
use SineMacula\Laravel\Authorization\Console\WhyCanCommand;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Http\Middleware\AuthorizeAction;
use SineMacula\Laravel\Authorization\Http\Middleware\RequirePermission;
use SineMacula\Laravel\Authorization\Http\Middleware\RequireRole;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\PermissionService;
use SineMacula\Laravel\Authorization\Services\PolicyService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;

/**
 * Service provider for the authorization package.
 *
 * Orchestrates the package's container bindings, config validation, publishing,
 * command registration, and boot-time wiring. Delegates the bulkier
 * responsibilities to dedicated registrars:
 *
 * - `GateRegistrar` — walks every configured permission enum and registers a
 *   matching Laravel Gate.
 * - `BladeDirectiveRegistrar` — wires the `@role` / `@permission` directive
 *   quartet and Spatie-compat aliases.
 *
 * Every binding that holds state for one request or job (the resolvers, the
 * policy store, the resolved tenant, the resolution cache, the last decision
 * and the manager that holds them) is registered with `scoped()`, so Laravel's
 * queue worker drops it before each job and Octane builds it afresh on each
 * request's sandbox. They are scoped together: a singleton holding a scoped
 * instance would keep the old instance alive.
 *
 * The management services (roles, permissions, policies and grants) hold no
 * state and are bound as singletons.
 *
 * The contracts an application may bind itself (the subject resolver, the
 * policy store and the policy resolver) resolve through a package-owned key
 * that holds the scoped default. An application's own binding of the contract
 * therefore replaces the default without being scoped itself, and an instance
 * it binds survives the reset between jobs.
 *
 * Row-lifecycle behaviour for `Role` / `Permission` / `Policy` is attached via
 * the `#[ObservedBy]` attribute on each model; the service provider does not
 * touch model booting.
 *
 * Booting never queries or writes the database, so `config:cache`,
 * `route:cache` and `migrate` run before the package's tables exist, and a
 * configured permission provider is never read at boot. The permission
 * catalogue the enums and providers declare reaches the database only when
 * `authorization:sync` runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuthorizationServiceProvider extends ServiceProvider
{
    /** @var string Prefix of the package-owned keys that hold each contract's scoped default. */
    private const string DEFAULT_BINDING_PREFIX = 'authorization.default:';

    /**
     * Register container bindings.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/authorization.php', 'authorization');

        $this->registerSubjectResolver();
        $this->registerTenantTree();
        $this->registerResolvedTenant();
        $this->registerPolicyStore();
        $this->registerResolutionCache();
        $this->registerPolicyResolver();
        $this->registerLastDecisionStore();
        $this->registerPolicyEvaluator();
        $this->registerAuthorizationManager();
        $this->registerManagementServices();
    }

    /**
     * Boot the provider.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GateConflictException
     */
    public function boot(): void
    {
        $this->validateConfig();
        $this->loadTranslationsFrom(__DIR__ . '/../lang', 'authorization');
        $this->offerPublishing();
        $this->registerCommands();

        (new GateRegistrar($this->app))->register();

        $this->registerRouteMiddleware();

        (new BladeDirectiveRegistrar($this->app))->register();
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
            WhyCanCommand::class,
            MigrateSpatieCommand::class,
            SyncPermissionsCommand::class,
            PruneGrantsCommand::class,
        ]);
    }

    /**
     * Bind the configured subject resolver as the default, scoped to the
     * request or job so any state it keeps does not reach the next one.
     *
     * @return void
     */
    protected function registerSubjectResolver(): void
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Contracts\SubjectResolver> $class */
        $class = $this->app['config']->get('authorization.subject_resolver', AuthGuardSubjectResolver::class);

        $this->forgetResolutionsOnRebinding(SubjectResolver::class);
        $this->bindScopedDefault(SubjectResolver::class, $class);
    }

    /**
     * Bind the configured tenant tree as the default, scoped to the request or
     * job like the subject resolver.
     *
     * @return void
     */
    protected function registerTenantTree(): void
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Contracts\TenantTree> $class */
        $class = $this->app['config']->get('authorization.tenant_tree', FlatTenantTree::class);

        $this->forgetResolutionsOnRebinding(TenantTree::class);
        $this->bindScopedDefault(TenantTree::class, $class);
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

            return ResolvedTenant::from($resolver);
        });
    }

    /**
     * Bind the configured policy store, when there is one, as the default,
     * scoped to the request or job so any state it keeps does not reach the
     * next one.
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

        $this->bindScopedDefault(PolicyStore::class, $class);
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

            return new ResolutionCache(store: $store, ttl: $ttl, prefix: $prefix);
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
        $this->bindScopedDefault(PolicyResolver::class, static fn (Application $app): PolicyResolver => new DefaultPolicyResolver(
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
     * Bind the policy evaluator.
     *
     * @return void
     */
    protected function registerPolicyEvaluator(): void
    {
        $this->app->scoped(PolicyEvaluator::class);
    }

    /**
     * Bind the authorization manager, scoped to the request or job together
     * with the resolvers and stores it holds.
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
        ));

        $this->app->alias('authorization', AuthorizationManager::class);
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
     * policy or grant. They hold no state, so each is a singleton.
     *
     * @return void
     */
    private function registerManagementServices(): void
    {
        foreach ([RoleService::class, PermissionService::class, PolicyService::class, GrantService::class] as $service) {
            $this->app->singleton($service);
        }
    }

    /**
     * Empty the resolution cache's memo whenever the abstract is rebound, as
     * replacing the subject resolver or the held tenant changes the tenant the
     * memo's entries were resolved under.
     *
     * Registered once, before the abstract is first bound: `rebinding()`
     * resolves an abstract that is already bound, and nothing may be resolved
     * while the provider registers.
     *
     * @param  string  $abstract
     * @return void
     */
    private function forgetResolutionsOnRebinding(string $abstract): void
    {
        if ($this->app->bound($abstract)) {
            return;
        }

        // @phpstan-ignore staticMethod.dynamicCall
        $this->app->rebinding($abstract, static function (): void {
            ResolutionCache::instance()?->tenantChanged();
        });
    }

    /**
     * Bind a contract an application may bind itself to the package's default,
     * built once per request or job.
     *
     * The default is held under a package-owned key bound with `scoped()`, and
     * the contract resolves through that key. Only the package-owned key is
     * scoped, so an application that binds the contract itself (with
     * `instance()`, `singleton()` or `bind()`) keeps its binding across the
     * reset between jobs, while the package's default is still rebuilt for each
     * one.
     *
     * @param  class-string  $contract
     * @param  class-string|\Closure(\Illuminate\Contracts\Foundation\Application): object  $concrete
     * @return void
     */
    private function bindScopedDefault(string $contract, \Closure|string $concrete): void
    {
        $default = self::DEFAULT_BINDING_PREFIX . $contract;

        $this->app->scoped($default, $concrete);
        $this->app->bind($contract, static fn (Application $app): mixed => $app->make($default));
    }
}
