<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;
use SineMacula\Laravel\Authorization\Contracts\PolicyRepository;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Exceptions\GateConflictException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Repositories\DefaultPolicyRepository;
use SineMacula\Laravel\Authorization\Resolvers\NullPrincipalResolver;

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
        $this->offerPublishing();
        $this->registerGates();
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
     * Bind the policy repository — the internal policy-gathering
     * seam the manager consults on every evaluation. Defaults to
     * `DefaultPolicyRepository`, which unions an optional
     * `PolicyStore` with the principal's own attached policies.
     *
     * @return void
     */
    protected function registerPolicyRepository(): void
    {
        $this->app->singleton(PolicyRepository::class, static fn (Application $app): PolicyRepository => new DefaultPolicyRepository(
            store: $app->bound(PolicyStore::class) ? $app->make(PolicyStore::class) : null,
        ));
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
     * Walk every configured permission enum and register a Gate per
     * case.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GateConflictException
     */
    protected function registerGates(): void
    {
        /** @var array<int, mixed> $enums */
        $enums = $this->app['config']->get('authorization.permission_enums', []);
        /** @var string $onConflict */
        $onConflict = $this->app['config']->get('authorization.gate.on_conflict', 'log');

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
     * @param  string  $onConflict
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GateConflictException
     */
    private function registerEnumGate(PermissionEnum $case, string $onConflict): void
    {
        $permission = $case->toString();

        if (Gate::has($permission)) {
            match ($onConflict) {
                'throw'     => throw new GateConflictException($permission),
                'overwrite' => null,
                default     => $this->logGateConflict($permission),
            };

            if ($onConflict === 'log') {
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
