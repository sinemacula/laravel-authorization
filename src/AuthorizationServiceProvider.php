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
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;
use SineMacula\Laravel\Authorization\Contracts\PolicyRepository;
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
use SineMacula\Laravel\Authorization\Repositories\CachingPolicyRepository;
use SineMacula\Laravel\Authorization\Repositories\DefaultPolicyRepository;
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
        $this->registerPolicyRepository();
        $this->registerDecisionJournal();
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
        $this->registerGates();
        $this->registerCacheInvalidationListeners();
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
     * Bind the policy repository — the internal policy-gathering
     * seam the manager consults on every evaluation. The default
     * implementation unions an optional `PolicyStore` with the
     * principal's own attached policies; the caching decorator
     * wraps it so the `ResolutionCache` memoises the result.
     *
     * @return void
     */
    protected function registerPolicyRepository(): void
    {
        $this->app->singleton(PolicyRepository::class, static function (Application $app): PolicyRepository {
            $default = new DefaultPolicyRepository(
                store: $app->bound(PolicyStore::class) ? $app->make(PolicyStore::class) : null,
            );

            return new CachingPolicyRepository(
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
     * Bind the decision journal that holds the most recent
     * evaluation result across every scoped clone of the manager.
     *
     * @return void
     */
    protected function registerDecisionJournal(): void
    {
        $this->app->singleton(DecisionJournal::class);
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
            resolver: $app->make(PrincipalResolver::class),
            repository: $app->make(PolicyRepository::class),
            journal: $app->make(DecisionJournal::class),
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
     * aliases (`@hasrole`, `@hasanyrole`, `@hasallroles`) are
     * registered in parallel so consumers migrating from Spatie
     * can move their views verbatim.
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
        $permissionNames = ['permission', 'anypermission', 'allpermissions'];

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
        $rawMode    = $this->app['config']->get('authorization.gate.on_conflict', GateConflictMode::LOG->value);
        $onConflict = $rawMode instanceof GateConflictMode
            ? $rawMode
            : (\is_string($rawMode) ? GateConflictMode::tryFrom($rawMode) : null) ?? GateConflictMode::LOG;

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

        // Single decision point for every conflict mode. Each arm
        // either short-circuits (log / throw) or falls through to
        // the define call below (overwrite, and the no-conflict
        // happy path).
        if (Gate::has($permission)) {
            switch ($onConflict) {
                case GateConflictMode::THROW:
                    throw new GateConflictException($permission);

                case GateConflictMode::OVERWRITE:
                    break;

                case GateConflictMode::LOG:
                    $this->logGateConflict($permission);

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
