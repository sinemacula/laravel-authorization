<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Exceptions\GateConflictException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
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
            store: $app->bound(PolicyStore::class) ? $app->make(PolicyStore::class) : null,
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
            static function (?object $user = null) use ($permission): bool {
                if ($user === null) {
                    return Authorization::can($permission);
                }

                return Authorization::for($user)->can($permission);
            },
        );
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
