<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Console\GrantRoleCommand;
use SineMacula\Laravel\Authorization\Console\ListPermissionsCommand;
use SineMacula\Laravel\Authorization\Console\ListRolesCommand;
use SineMacula\Laravel\Authorization\Console\MigrateSpatieCommand;
use SineMacula\Laravel\Authorization\Console\RevokeRoleCommand;
use SineMacula\Laravel\Authorization\Console\WhyCanCommand;
use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Http\Middleware\RequirePermission;
use SineMacula\Laravel\Authorization\Http\Middleware\RequireRole;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Resolvers\CachingPolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\NullPrincipalResolver;
use SineMacula\Laravel\Authorization\Resolvers\NullTenantResolver;

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
 * - `EventListenerRegistrar` — wires the resolution-cache invalidator and the
 *   Octane request-boundary reset.
 *
 * Row-lifecycle behaviour for `Role` / `Permission` / `Policy` is attached via
 * the `#[ObservedBy]` attribute on each model; the service provider does not
 * touch model booting.
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

        $this->registerPrincipalResolver();
        $this->registerTenantResolver();
        $this->registerPolicyStore();
        $this->registerResolutionCache();
        $this->registerPolicyResolver();
        $this->registerLastDecisionStore();
        $this->registerPolicyEvaluator();
        $this->registerAuthorizationManager();
    }

    /**
     * Boot the provider.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->validateConfig();
        $this->offerPublishing();
        $this->registerCommands();

        (new GateRegistrar($this->app))->register();

        $this->registerPermissionProviders();

        (new EventListenerRegistrar($this->app))->register();

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
        ]);
    }

    /**
     * Bind the principal resolver.
     *
     * @return void
     */
    protected function registerPrincipalResolver(): void
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Contracts\PrincipalResolver> $class */
        $class = $this->app['config']->get('authorization.principal_resolver', NullPrincipalResolver::class);

        $this->app->singleton(PrincipalResolver::class, $class);
    }

    /**
     * Bind the tenant resolver.
     *
     * @return void
     */
    protected function registerTenantResolver(): void
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Contracts\TenantResolver> $class */
        $class = $this->app['config']->get('authorization.tenant_resolver', NullTenantResolver::class);

        $this->app->singleton(TenantResolver::class, $class);
    }

    /**
     * Bind the optional policy store.
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

        $this->app->singleton(PolicyStore::class, $class);
    }

    /**
     * Bind the resolution cache that memoises policy, permission, and role
     * lookups per-principal. Always on for in-memory memoisation; consults
     * `authorization.cache.store` for optional cross-request persistence.
     *
     * @return void
     */
    protected function registerResolutionCache(): void
    {
        $this->app->singleton(ResolutionCache::class, static function (Application $app): ResolutionCache {
            /** @var string|null $storeName */
            $storeName = $app['config']->get('authorization.cache.store');
            /** @var int $ttl */
            $ttl = (int) $app['config']->get('authorization.cache.ttl', 0);
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
     * optional `PolicyStore` with the principal's own attached policies; the
     * caching decorator wraps it so the `ResolutionCache` memoises the result.
     *
     * @return void
     */
    protected function registerPolicyResolver(): void
    {
        $this->app->singleton(PolicyResolver::class, static function (Application $app): PolicyResolver {
            $default = new DefaultPolicyResolver(
                store: $app->bound(PolicyStore::class) ? $app->make(PolicyStore::class) : null,
            );

            return new CachingPolicyResolver(
                inner: $default,
                cache: $app->make(ResolutionCache::class),
            );
        });
    }

    /**
     * Bind the single-slot store that holds the most recent evaluation result
     * across every scoped clone of the manager.
     *
     * @return void
     */
    protected function registerLastDecisionStore(): void
    {
        $this->app->singleton(LastDecisionStore::class);
    }

    /**
     * Bind the policy evaluator.
     *
     * @return void
     */
    protected function registerPolicyEvaluator(): void
    {
        $this->app->singleton(PolicyEvaluator::class);
    }

    /**
     * Bind the authorization manager.
     *
     * @return void
     */
    protected function registerAuthorizationManager(): void
    {
        $this->app->singleton('authorization', static fn (Application $app): AuthorizationManager => new AuthorizationManager(
            evaluator: $app->make(PolicyEvaluator::class),
            principalResolver: $app->make(PrincipalResolver::class),
            policyResolver: $app->make(PolicyResolver::class),
            lastDecisionStore: $app->make(LastDecisionStore::class),
            events: $app->bound(Dispatcher::class) ? $app->make(Dispatcher::class) : null,
        ));

        $this->app->alias('authorization', AuthorizationManager::class);
    }

    /**
     * Register the `role` and `permission` route-middleware aliases.
     *
     * The aliases only light up when the `router` binding is available
     * (Laravel's default HTTP kernel), so console-only applications that do not
     * resolve the router never pay the registration cost. Existing aliases on
     * the same keys are respected — a consumer that has already wired their own
     * `role` or `permission` middleware keeps theirs untouched.
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

        /** @var array<string, class-string> $existing */
        $existing = $router->getMiddleware();

        if (!isset($existing['role'])) {
            $router->aliasMiddleware('role', RequireRole::class);
        }

        if (isset($existing['permission'])) {
            return;
        }

        $router->aliasMiddleware('permission', RequirePermission::class);
    }

    /**
     * Offer config and migration publishing.
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
    }

    /**
     * Walk every configured permission provider and create `Permission` rows
     * for each string the provider declares.
     *
     * Providers are instantiated through the container so they can inject
     * dependencies. Each permission string is persisted via `firstOrCreate`
     * keyed on `(name, guard_name)` so the method is idempotent across boots.
     *
     * @return void
     */
    protected function registerPermissionProviders(): void
    {
        /** @var array<int, mixed> $providers */
        $providers = $this->app['config']->get('authorization.permission_providers', []);

        if ($providers === []) {
            return;
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $permissionModel */
        $permissionModel = $this->app['config']->get('authorization.models.permission', Permission::class);

        foreach ($providers as $providerClass) {
            if (!\is_string($providerClass) || !\is_subclass_of($providerClass, PermissionProvider::class)) {
                continue;
            }

            $this->syncProviderPermissions($providerClass, $permissionModel);
        }
    }

    /**
     * Persist a single provider's permission strings for its guard scope.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Contracts\PermissionProvider>  $providerClass
     * @param  class-string<\SineMacula\Laravel\Authorization\Models\Permission>  $permissionModel
     * @return void
     */
    protected function syncProviderPermissions(string $providerClass, string $permissionModel): void
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\PermissionProvider $provider */
        $provider = $this->app->make($providerClass);

        $guard = $provider->guard();

        foreach ($provider->permissions() as $permission) {
            // Load-bearing guard against providers whose runtime return
            // violates the string-list contract, despite the contract narrowing
            // making it read as redundant.
            // @phpstan-ignore function.alreadyNarrowedType
            if (!\is_string($permission) || $permission === '') {
                continue;
            }

            $permissionModel::firstOrCreate(
                ['name' => $permission, 'guard_name' => $guard],
            );
        }
    }
}
