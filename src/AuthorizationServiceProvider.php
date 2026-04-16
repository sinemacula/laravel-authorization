<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Console\GrantRoleCommand;
use SineMacula\Laravel\Authorization\Console\ListPermissionsCommand;
use SineMacula\Laravel\Authorization\Console\ListRolesCommand;
use SineMacula\Laravel\Authorization\Console\MigrateSpatieCommand;
use SineMacula\Laravel\Authorization\Console\RevokeRoleCommand;
use SineMacula\Laravel\Authorization\Console\WhyCanCommand;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;
use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Enums\GateConflictMode;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Events\IdentityPermissionGranted;
use SineMacula\Laravel\Authorization\Events\IdentityPermissionRevoked;
use SineMacula\Laravel\Authorization\Events\IdentityPolicyAttached;
use SineMacula\Laravel\Authorization\Events\IdentityPolicyDetached;
use SineMacula\Laravel\Authorization\Events\IdentityRoleAssigned;
use SineMacula\Laravel\Authorization\Events\IdentityRoleRevoked;
use SineMacula\Laravel\Authorization\Events\RolePermissionGranted;
use SineMacula\Laravel\Authorization\Events\RolePermissionRevoked;
use SineMacula\Laravel\Authorization\Exceptions\GateConflictException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Http\Middleware\RequirePermission;
use SineMacula\Laravel\Authorization\Http\Middleware\RequireRole;
use SineMacula\Laravel\Authorization\Listeners\InvalidateResolutionCache;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Resolvers\CachingPolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\NullPrincipalResolver;
use SineMacula\Laravel\Authorization\Support\BladeHelpers;

/**
 * Service provider for the authorization package.
 *
 * Registers the authorization manager, the evaluator, the principal
 * resolver and (optionally) a policy store. Publishes the shipped
 * config file and the migration directory, and walks every
 * configured permission enum to register matching Laravel Gates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class AuthorizationServiceProvider extends ServiceProvider
{
    /**
     * Register container bindings.
     *
     * @return void
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/authorization.php', 'authorization');

        $this->registerPrincipalResolver();
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
        $this->registerGates();
        $this->registerPermissionProviders();
        $this->registerCacheInvalidationListeners();
        $this->registerOctaneResetListener();
        $this->registerRouteMiddleware();
        $this->registerBladeDirectives();
    }

    /**
     * Fail fast on a malformed `authorization` config. Runs before
     * any binding is resolved so a typo surfaces as a clear typed
     * exception rather than a deep stack trace from the first
     * `can()` call in production.
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
     * Register the package's Artisan commands when the application
     * is running in the console.
     *
     * @return void
     */
    protected function registerCommands(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                ListRolesCommand::class,
                ListPermissionsCommand::class,
                GrantRoleCommand::class,
                RevokeRoleCommand::class,
                WhyCanCommand::class,
                MigrateSpatieCommand::class,
            ]);
        }
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
     * Bind the optional policy store.
     *
     * @return void
     */
    protected function registerPolicyStore(): void
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Contracts\PolicyStore>|null $class */
        $class = $this->app['config']->get('authorization.policy_store');

        if ($class !== null) {
            $this->app->singleton(PolicyStore::class, $class);
        }
    }

    /**
     * Bind the resolution cache that memoises policy, permission,
     * and role lookups per-principal. Always on for in-memory
     * memoisation; consults `authorization.cache.store` for
     * optional cross-request persistence.
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
     * Bind the policy resolver — the internal policy-gathering
     * seam the manager consults on every evaluation. The default
     * implementation unions an optional `PolicyStore` with the
     * principal's own attached policies; the caching decorator
     * wraps it so the `ResolutionCache` memoises the result.
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
     * Wire the invalidation listener to every event that mutates
     * a principal's cached lookups.
     *
     * @return void
     */
    protected function registerCacheInvalidationListeners(): void
    {
        if (!$this->app->bound(Dispatcher::class)) {
            return;
        }

        /** @var \Illuminate\Contracts\Events\Dispatcher $dispatcher */
        $dispatcher = $this->app->make(Dispatcher::class);

        $principalEvents = [
            IdentityRoleAssigned::class,
            IdentityRoleRevoked::class,
            IdentityPermissionGranted::class,
            IdentityPermissionRevoked::class,
            IdentityPolicyAttached::class,
            IdentityPolicyDetached::class,
        ];

        foreach ($principalEvents as $event) {
            $dispatcher->listen($event, [InvalidateResolutionCache::class, 'handlePrincipalMutation']);
        }

        foreach ([RolePermissionGranted::class, RolePermissionRevoked::class] as $event) {
            $dispatcher->listen($event, [InvalidateResolutionCache::class, 'handleRoleMutation']);
        }
    }

    /**
     * Bind the single-slot store that holds the most recent
     * evaluation result across every scoped clone of the manager.
     *
     * @return void
     */
    protected function registerLastDecisionStore(): void
    {
        $this->app->singleton(LastDecisionStore::class);
    }

    /**
     * Wire an Octane request-boundary listener that clears the
     * last-decision store between requests.
     *
     * The store is bound as a container singleton, so under Octane
     * (or RoadRunner / Swoole / FrankenPHP) the slot survives
     * across requests and would otherwise leak the previous
     * request's decision into the next one's `lastDecision()`
     * accessor. The listener is wired only when Octane's
     * `RequestTerminated` event class is present in the host
     * application — keeping the package free of a hard Octane
     * dependency while auto-resetting when Octane is installed.
     *
     * @return void
     */
    protected function registerOctaneResetListener(): void
    {
        $event = 'Laravel\Octane\Events\RequestTerminated';

        if (!\class_exists($event) || !$this->app->bound(Dispatcher::class)) {
            return;
        }

        /** @var \Illuminate\Contracts\Events\Dispatcher $dispatcher */
        $dispatcher = $this->app->make(Dispatcher::class);

        $app = $this->app;

        $dispatcher->listen($event, static function () use ($app): void {
            if ($app->bound(LastDecisionStore::class)) {
                $app->make(LastDecisionStore::class)->reset();
            }
        });
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
     * The aliases only light up when the `router` binding is
     * available (Laravel's default HTTP kernel), so console-only
     * applications that do not resolve the router never pay the
     * registration cost. Existing aliases on the same keys are
     * respected — a consumer that has already wired their own
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

        if (!isset($existing['permission'])) {
            $router->aliasMiddleware('permission', RequirePermission::class);
        }
    }

    /**
     * Register Blade directives for role and permission checks.
     *
     * `Blade::if('role', …)` auto-generates the paired
     * `@role / @unlessrole / @elserole / @endrole` quartet; the
     * same pattern covers `@permission`, `@anyrole`, `@allroles`,
     * `@anypermission`, and `@allpermissions`. Spatie-style
     * aliases (`@hasrole`, `@hasanyrole`, `@hasallroles`,
     * `@haspermission`, `@hasanypermission`, `@hasallpermissions`)
     * are registered in parallel so consumers migrating from
     * Spatie can move their views verbatim.
     *
     * Spatie closes its unless-variants with `@endunless<name>`,
     * whereas `Blade::if` closes its auto-generated variant with
     * `@end<name>`. Every canonical and compat name gets a
     * matching `@endunless<name>` alias that emits the same
     * `endif;`, so both idioms compile cleanly regardless of
     * which closing spelling the consumer reaches for (see issue
     * #86).
     *
     * The directives are registered only when the `blade.compiler`
     * binding is present, so console-only applications that do not
     * resolve the view layer never pay the registration cost.
     *
     * @return void
     */
    protected function registerBladeDirectives(): void
    {
        if (!$this->app->bound('blade.compiler')) {
            return;
        }

        $roleNames       = ['role', 'anyrole', 'allroles', 'hasrole', 'hasanyrole', 'hasallroles'];
        $permissionNames = ['permission', 'anypermission', 'allpermissions', 'haspermission', 'hasanypermission', 'hasallpermissions'];

        $anyRole = static fn (array|string $roles): bool => BladeHelpers::hasRole($roles);
        $allRole = static fn (array|string $roles): bool => BladeHelpers::hasAllRoles($roles);
        $anyPerm = static fn (array|string $permissions): bool => BladeHelpers::hasPermission($permissions);
        $allPerm = static fn (array|string $permissions): bool => BladeHelpers::hasAllPermissions($permissions);

        Blade::if('role', $anyRole);
        Blade::if('anyrole', $anyRole);
        Blade::if('allroles', $allRole);
        Blade::if('hasrole', $anyRole);
        Blade::if('hasanyrole', $anyRole);
        Blade::if('hasallroles', $allRole);

        Blade::if('permission', $anyPerm);
        Blade::if('anypermission', $anyPerm);
        Blade::if('allpermissions', $allPerm);
        Blade::if('haspermission', $anyPerm);
        Blade::if('hasanypermission', $anyPerm);
        Blade::if('hasallpermissions', $allPerm);

        foreach ([...$roleNames, ...$permissionNames] as $name) {
            Blade::directive('endunless' . $name, static fn (): string => '<?php endif; ?>');
        }
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
     * Walk every configured permission enum and register a Gate
     * per case.
     *
     * Laravel's Gate never dispatches to an action it has not
     * been told about, so an empty `authorization.permission_enums`
     * config leaves `Gate::allows(...)`, `$user->can(...)`,
     * `@can(...)`, and the `can:` middleware silent — they
     * return false for every action. The `Authorization` facade
     * still works out of the box; the Gate surface only lights
     * up once a `PermissionEnum` is registered here. Consumers
     * using the facade exclusively can leave the config empty
     * and the method is a no-op.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GateConflictException
     */
    protected function registerGates(): void
    {
        /** @var array<int, mixed> $enums */
        $enums = $this->app['config']->get('authorization.permission_enums', []);

        /** @var mixed $rawMode */
        $rawMode    = $this->app['config']->get('authorization.gate.on_conflict', GateConflictMode::THROW->value);
        $onConflict = $rawMode instanceof GateConflictMode
            ? $rawMode
            : (\is_string($rawMode) ? GateConflictMode::tryFrom($rawMode) : null) ?? GateConflictMode::THROW;

        foreach ($enums as $enumClass) {
            if (!\is_string($enumClass) || !\is_subclass_of($enumClass, PermissionEnum::class)) {
                continue;
            }

            /** @var class-string<\SineMacula\Laravel\Authorization\Contracts\PermissionEnum> $className */
            $className = $enumClass;

            foreach ($className::cases() as $case) {
                $this->registerEnumGate($case, $onConflict);
            }
        }
    }

    /**
     * Walk every configured permission provider and create
     * `Permission` rows for each string the provider declares.
     *
     * Providers are instantiated through the container so they can
     * inject dependencies. Each permission string is persisted via
     * `firstOrCreate` keyed on `(name, guard_name)` so the method
     * is idempotent across boots.
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

            /** @var \SineMacula\Laravel\Authorization\Contracts\PermissionProvider $provider */
            $provider = $this->app->make($providerClass);

            $guard = $provider->guard();

            foreach ($provider->permissions() as $permission) {
                if (!\is_string($permission) || $permission === '') {
                    continue;
                }

                $permissionModel::firstOrCreate(
                    ['name' => $permission, 'guard_name' => $guard],
                );
            }
        }
    }

    /**
     * Register a single Gate for the supplied enum case.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\PermissionEnum  $case
     * @param  \SineMacula\Laravel\Authorization\Enums\GateConflictMode  $onConflict
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GateConflictException
     */
    private function registerEnumGate(PermissionEnum $case, GateConflictMode $onConflict): void
    {
        $permission = $case->toString();

        // Single decision point for every conflict mode. `match`
        // over the enum is exhaustive at PHPStan level 8 — adding
        // a future `GateConflictMode` case becomes a clear
        // "unhandled match" error here rather than silent
        // fall-through under `switch`. THROW short-circuits with
        // an exception, OVERWRITE proceeds to redefine the gate,
        // and LOG records the conflict and abandons the redefine.
        if (Gate::has($permission)) {
            $shouldDefine = match ($onConflict) {
                GateConflictMode::THROW     => throw new GateConflictException($permission),
                GateConflictMode::OVERWRITE => true,
                GateConflictMode::LOG       => (function () use ($permission): bool {
                    $this->logGateConflict($permission);

                    return false;
                })(),
            };

            if (!$shouldDefine) {
                return;
            }
        }

        Gate::define(
            $permission,
            static function (?object $user = null, mixed ...$arguments) use ($permission): bool {
                [$resource, $context] = self::translateGateArguments($arguments);

                if ($user === null) {
                    return Authorization::can($permission, $resource, $context);
                }

                return Authorization::for($user)->can($permission, $resource, $context);
            },
        );
    }

    /**
     * Translate the arguments Laravel hands to a Gate callback into
     * the `(resource, context)` pair the authorization manager
     * accepts.
     *
     * Laravel's Gate spreads the argument tail into the callback
     * with PHP's `...` operator, so an associative array ends up in
     * the variadic parameter under its original string keys rather
     * than at numeric index 0. The translation treats positional
     * entries (integer keys) and named entries (string keys)
     * separately:
     *
     * - The first positional argument is the resource identifier.
     *   Strings pass through unchanged, Eloquent models become
     *   `{morphClass}:{key}` (matching the polymorphic pivots'
     *   convention — register a morph alias on the consumer side
     *   to avoid FQN backslashes leaking into resource strings),
     *   stringable objects are cast via `__toString`, and anything
     *   else yields a null resource.
     * - A positional array at index 0 that is string-keyed is
     *   treated as a context map with no resource, covering the
     *   `Gate::allows('edit', ['tenant' => '…'])` idiom.
     * - Any string-keyed array found after the resource slot is
     *   merged into the context. String-keyed entries in the
     *   variadic itself (PHP spread of an assoc array) flow
     *   directly into the context.
     * - Unmappable trailing positional values are discarded rather
     *   than guessed at.
     *
     * @param  array<int|string, mixed>  $arguments
     * @return array{0: string|null, 1: array<string, mixed>}
     */
    private static function translateGateArguments(array $arguments): array
    {
        if ($arguments === []) {
            return [null, []];
        }

        $resource = null;
        $context  = [];

        foreach ($arguments as $key => $value) {
            if (\is_string($key)) {
                $context[$key] = $value;

                continue;
            }

            if ($key === 0) {
                if (\is_array($value) && !\array_is_list($value)) {
                    /** @var array<string, mixed> $value */
                    $context = \array_merge($context, $value);
                } else {
                    $resource = self::stringifyGateResource($value);
                }

                continue;
            }

            if (\is_array($value) && !\array_is_list($value)) {
                /** @var array<string, mixed> $value */
                $context = \array_merge($context, $value);
            }
        }

        return [$resource, $context];
    }

    /**
     * Coerce a Gate-callback argument into a resource identifier
     * string. Returns null when the value is not a resource the
     * evaluator can reason about.
     *
     * @param  mixed  $value
     * @return string|null
     */
    private static function stringifyGateResource(mixed $value): ?string
    {
        if (\is_string($value)) {
            return $value;
        }

        if ($value instanceof AuthorizableResource) {
            return $value->toResourceIdentifier();
        }

        if ($value instanceof Model) {
            return $value->getMorphClass() . ':' . (string) $value->getKey();
        }

        if (\is_object($value) && \method_exists($value, '__toString')) {
            return (string) $value;
        }

        return null;
    }

    /**
     * Emit the configured conflict warning.
     *
     * @param  string  $permission
     * @return void
     */
    private function logGateConflict(string $permission): void
    {
        try {
            Log::channel('authorization')->warning(
                "Authorization gate '{$permission}' already registered; existing Gate preserved.",
            );
        } catch (\Throwable) {
            Log::warning(
                "Authorization gate '{$permission}' already registered; existing Gate preserved.",
            );
        }
    }
}
