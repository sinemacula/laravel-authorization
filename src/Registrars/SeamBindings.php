<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Registrars;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Application as FoundationApplication;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Hooks\GrantHooks;
use SineMacula\Laravel\Authorization\Hooks\ListedGrantHooks;

/**
 * Bind the seams an application may bind itself: the contracts the package
 * gives a default for, the classes the configuration names in place of a
 * default, and the hooks the configuration lists.
 *
 * Each default is held under a package-owned key bound with `scoped()`, and the
 * contract resolves through that key. Only the package-owned key is scoped, so
 * an application that binds the contract itself (with `instance()`,
 * `singleton()`, `scoped()` or `bind()`) keeps its binding across the reset
 * between jobs, while the package's default is still rebuilt for each one.
 *
 * A contract is bound to its key only when nothing is bound to it yet (N103): a
 * binding a sibling package or the application made before the package
 * registers stands, and one made afterwards replaces the default. A class the
 * configuration names in place of the package's default is the application's
 * explicit choice, so the contract is bound to it over whatever was bound
 * before (N106), a deferred provider's binding included, and a binding made
 * afterwards still replaces it. The grant hook is the one exception: the hooks
 * the configuration lists run before whatever it resolves to (N108).
 *
 * Nothing is resolved here, but as Laravel resolves a contract it rebinds or
 * extends for the callbacks that watch it with `rebinding()` or `refresh()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SeamBindings
{
    /** @var string Prefix of the package-owned keys that hold each contract's scoped default. */
    private const string DEFAULT_BINDING_PREFIX = 'authorization.default:';

    /**
     * Create a new registrar instance.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     */
    public function __construct(

        /** The application the seams are bound in. */
        private Application $app,
    ) {}

    /**
     * Bind a contract to the class the configuration key names, the package's
     * default when it names none, built once per request or job.
     *
     * A class other than the package's default is the application's explicit
     * choice, so it replaces a binding a sibling package made before the
     * package registers (N106); the package's default gives way to one.
     *
     * @param  class-string  $contract
     * @param  string  $key
     * @param  class-string  $default
     * @return void
     */
    public function bindConfigured(string $contract, string $key, string $default): void
    {
        /** @var class-string $class */
        $class = $this->app['config']->get($key, $default);

        $this->bindDefault($contract, $class, $class !== $default);
    }

    /**
     * Bind a contract an application may bind itself to the package's default,
     * built once per request or job, under the package-owned key that keeps the
     * default reachable whatever the contract resolves to.
     *
     * The contract is bound to the key only when nothing is bound to it yet
     * (N103). When the concrete is a class the application configured (N106),
     * the contract is bound to the key over whatever was bound before, a
     * deferred provider's binding included, and a binding made afterwards still
     * replaces it.
     *
     * Binding the configured class follows Laravel's rules for any binding: an
     * extender registered on the contract is applied to it, so one typed to a
     * sibling package's class fails, and over a contract already resolved the
     * callbacks watching it with `rebinding()` or `refresh()` are called, which
     * may resolve the configured class while the package registers.
     *
     * @param  class-string  $contract
     * @param  class-string|\Closure(\Illuminate\Contracts\Foundation\Application): object  $concrete
     * @param  bool  $configured
     * @return void
     */
    public function bindDefault(string $contract, \Closure|string $concrete, bool $configured = false): void
    {
        $default = self::DEFAULT_BINDING_PREFIX . $contract;
        $resolve = static fn (Application $app): mixed => $app->make($default);

        $this->app->scoped($default, $concrete);

        if (!$configured) {
            $this->app->bindIf($contract, $resolve);

            return;
        }

        $this->bindOverEarlierBindings($contract, $resolve);
    }

    /**
     * Bind the composite holding no hook as the grant hook's default, and, when
     * the configuration lists hooks, extend the contract so they run before
     * whatever it resolves to (N108).
     *
     * Laravel applies the extender each time it builds the contract, so the
     * hook is wrapped however it was bound: before the package registers or
     * after, with `bind()`, `singleton()` or `scoped()`, by a deferred
     * provider, or the default when nothing else is bound, which holds none of
     * the listed hooks. An extender registered on the contract before the
     * package's applies to the hook before it is wrapped, and one registered
     * after receives the wrapped hook. Laravel applies an extender to an
     * instance the container already holds once, at once, and to none it is
     * handed later, so the grant service wraps the hook it calls again, which a
     * hook already wrapped is not (see `WideningPhase`). With no hook listed no
     * extender is registered.
     *
     * Registering builds none of the listed hooks: the wrapped hook builds them
     * at its first use. It resolves the bound hook only when that was resolved
     * before and something watches the contract with `rebinding()` or
     * `refresh()`, as Laravel then hands the watcher the wrapped hook.
     *
     * @return void
     */
    public function bindGrantHooks(): void
    {
        $this->bindDefault(GrantHook::class, GrantHooks::class);

        if ($this->app['config']->get('authorization.grant_hooks', []) === []) {
            return;
        }

        $this->app->extend(GrantHook::class, ListedGrantHooks::around(...));
    }

    /**
     * Bind the contract to the default's key over whatever a sibling package
     * bound to it before the package registered (N106), a deferred provider's
     * binding included.
     *
     * A deferred provider that provides the contract would bind it at the
     * contract's first resolution, after the package, so it is loaded first and
     * its binding replaced. One the application knows of when the package
     * registers is loaded then. The application learns of the deferred
     * providers of its configuration and of package discovery only once it has
     * registered every eager provider, the package among them, so one it learns
     * of later is loaded, and the contract bound again, as the application
     * boots, when the contract has not been resolved by then.
     *
     * @param  class-string  $contract
     * @param  \Closure(\Illuminate\Contracts\Foundation\Application): mixed  $resolve
     * @return void
     */
    private function bindOverEarlierBindings(string $contract, \Closure $resolve): void
    {
        $bind = static function (Application $app) use ($contract, $resolve): void {
            if ($app instanceof FoundationApplication) {
                $app->loadDeferredProvider($contract);
            }

            $app->bind($contract, $resolve);
        };

        $bind($this->app);

        $this->app->booting(static function (Application $app) use ($contract, $bind): void {
            if (!$app instanceof FoundationApplication || !$app->isDeferredService($contract)) {
                return;
            }

            $bind($app);
        });
    }
}
