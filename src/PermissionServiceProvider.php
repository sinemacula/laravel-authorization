<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Permissions;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Iam\Permissions\Contracts\PermissionEnum;
use SineMacula\Laravel\Iam\Permissions\Contracts\PolicyStore;
use SineMacula\Laravel\Iam\Permissions\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Iam\Permissions\Facades\Permission;

/**
 * Permission service provider.
 *
 * Bootstraps the permissions sub-package including the permission
 * manager, policy evaluator, and Laravel Gate registrations.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
class PermissionServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../../config/iam-permissions.php', 'iam-permissions');

        $this->registerPolicyStore();
        $this->registerPolicyEvaluator();
        $this->registerPermissionManager();
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->offerPublishing();
        $this->registerGates();
    }

    /**
     * Register the policy store binding.
     *
     * @return void
     */
    protected function registerPolicyStore(): void
    {
        /** @var class-string<\SineMacula\Laravel\Iam\Permissions\Contracts\PolicyStore>|null $storeClass */
        $storeClass = $this->app['config']->get('iam-permissions.policy_store');

        if ($storeClass !== null) {
            $this->app->singleton(PolicyStore::class, $storeClass);
        }
    }

    /**
     * Register the policy evaluator.
     *
     * @return void
     */
    protected function registerPolicyEvaluator(): void
    {
        $this->app->singleton(PolicyEvaluator::class);
    }

    /**
     * Register the permission manager singleton.
     *
     * @return void
     */
    protected function registerPermissionManager(): void
    {
        $this->app->singleton('iam.permissions', fn (Application $app): PermissionManager => new PermissionManager(
            evaluator: $app->make(PolicyEvaluator::class),
            policyStore: $app->bound(PolicyStore::class) ? $app->make(PolicyStore::class) : null,
        ));

        $this->app->alias('iam.permissions', PermissionManager::class);
    }

    /**
     * Offer config publishing.
     *
     * @return void
     */
    protected function offerPublishing(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../../config/iam-permissions.php' => config_path('iam-permissions.php'),
            ], 'iam-permissions-config');
        }
    }

    /**
     * Register Laravel Gates for each configured permission enum.
     *
     * Iterates over the permission enum classes listed in the
     * configuration and defines a Gate for each enum case, enabling
     * standard Laravel authorization checks.
     *
     * @return void
     */
    protected function registerGates(): void
    {
        /** @var array<int, class-string<\SineMacula\Laravel\Iam\Permissions\Contracts\PermissionEnum>> $enums */
        $enums = $this->app['config']->get('iam-permissions.permission_enums', []);

        foreach ($enums as $enumClass) {
            if (!is_subclass_of($enumClass, PermissionEnum::class)) {
                continue;
            }

            foreach ($enumClass::cases() as $case) {
                $permission = $case->toString();

                Gate::define($permission, static fn (): bool => Permission::can($permission));
            }
        }
    }
}
