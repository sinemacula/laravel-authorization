<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Registrars;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Application as FoundationApplication;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Diagnostics\BindingRegistry;
use SineMacula\Laravel\Authorization\Diagnostics\ContainerState;
use SineMacula\Laravel\Authorization\Diagnostics\SeamRecord;
use SineMacula\Laravel\Authorization\Hooks\GrantHooks;
use SineMacula\Laravel\Authorization\Hooks\ListedGrantHooks;
use SineMacula\Laravel\Authorization\Support\ClassName;

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
 * The closure each contract is bound to is the service provider's: it is built
 * by the closure the provider hands the registrar, which the provider declares.
 * A sibling package reads the binding table to tell the package's default from
 * the application's own binding, by the class that declares the closure, and
 * replaces only the package's default, so a closure the registrar declared
 * itself would be taken for the application's and kept.
 *
 * Nothing is resolved here, but as Laravel resolves a contract it rebinds or
 * extends for the callbacks that watch it with `rebinding()` or `refresh()`.
 *
 * The configuration is read before it is validated, so a value that names no
 * class implementing the contract, null, a number or an empty string among
 * them, is taken for no configured class at all: the package's default is bound
 * as when nothing is configured, a binding made before the package registers
 * stands, and the application's boot refuses the value, naming the setting.
 * Telling such a value apart only checks its type and that the class exists and
 * implements the contract, so it resolves nothing. A value naming the default
 * class itself, whatever its case and with or without a leading backslash,
 * names the default, as PHP reads one class by each such name.
 *
 * Before binding a contract, what was bound to it already is recorded, with the
 * closure bound and the key it forwards to, in the registry the configuration
 * report reads (see `Diagnostics\BindingRegistry`), so the report can tell the
 * package's binding from one made before it registered and one made after.
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
     * @param  \Closure(string): (\Closure(\Illuminate\Contracts\Foundation\Application): mixed)  $resolving
     */
    public function __construct(

        /** The application the seams are bound in. */
        private Application $app,

        /** Build the closure a contract is bound to, resolving the package-owned key given; the service provider declares both. */
        private \Closure $resolving,
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
        $class      = $this->configuredClass($key, $contract, $default);
        $configured = !ClassName::areSame($class, $default);

        $this->bindDefault($contract, $configured ? $class : $default, $configured, $key);
    }

    /**
     * Return the class the configuration key names, or the default when it
     * names no existing class implementing the contract, which the
     * application's boot then refuses.
     *
     * @template TDefault of class-string|null
     *
     * @param  string  $key
     * @param  class-string  $contract
     * @param  TDefault  $default
     * @return class-string|TDefault
     */
    public function configuredClass(string $key, string $contract, ?string $default): ?string
    {
        $class = $this->app['config']->get($key, $default);

        return \is_string($class) && $class !== '' && \class_exists($class) && \is_a($class, $contract, true) ? $class : $default;
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
     * @param  string|null  $configKey
     * @param  class-string|null  $builds
     * @return \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord
     */
    public function bindDefault(string $contract, \Closure|string $concrete, bool $configured = false, ?string $configKey = null, ?string $builds = null): SeamRecord
    {
        $default = self::DEFAULT_BINDING_PREFIX . $contract;

        // The application's own choice is bound through a closure this class
        // declares, not the provider, so neither the provider's
        // isPackageDefault() nor a sibling reading the binding table takes it
        // for the package's default and replaces it.
        $binding = $configured
            ? static fn (Application $app): mixed => $app->make($default)
            : ($this->resolving)($default);

        $record = new SeamRecord($contract, $binding, $default, \is_string($concrete) ? $concrete : $builds, $configKey, $configured, ...$this->earlier($contract));

        $this->record($record);

        $this->app->scoped($default, $concrete);

        if ($configured) {
            $this->bindOverEarlierBindings($contract, $binding);
        } else {
            $this->app->bindIf($contract, $binding);
        }

        return $record;
    }

    /**
     * Bind a contract an application may bind itself to the closure, built once
     * for as long as the application runs, when nothing is bound to it yet
     * (N103), recording the binding as the defaults are.
     *
     * @param  class-string  $contract
     * @param  \Closure(\Illuminate\Contracts\Foundation\Application): object  $concrete
     * @param  class-string  $builds
     * @return void
     */
    public function bindSharedIf(string $contract, \Closure $concrete, string $builds): void
    {
        $this->record(new SeamRecord($contract, $concrete, null, $builds, null, false, ...$this->earlier($contract)));

        $this->app->singletonIf($contract, $concrete);
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
     * hook already wrapped is not (see `WideningPhase`). With no hook listed,
     * or a value that lists none, no extender is registered.
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
        $record = $this->bindDefault(GrantHook::class, GrantHooks::class);
        $hooks  = $this->app['config']->get('authorization.grant_hooks', []);

        // A value that is not a list of hooks is refused as the application
        // boots, so none is listed until then.
        if (!\is_array($hooks) || $hooks === []) {
            return;
        }

        $held = ContainerState::instance($this->app, GrantHook::class);

        $this->app->extend(GrantHook::class, ListedGrantHooks::around(...));

        // Laravel applies the extender at once to an instance it holds and
        // keeps no trace of it, so the decorator that replaced the instance is
        // recorded, for the report to tell it from a later binding.
        $wrapper = ContainerState::instance($this->app, GrantHook::class);

        if ($wrapper === $held) {
            return;
        }

        $this->record($record->wrappedBy($wrapper));
    }

    /**
     * Keep the record of a seam in the application's registry.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord  $record
     * @return void
     */
    private function record(SeamRecord $record): void
    {
        BindingRegistry::of($this->app)->record($record);
    }

    /**
     * Return what the contract was bound to before the package binds it: the
     * binding's closure and the instance held, either of which the report
     * matches with what supplies the contract when it runs (see
     * `CurrentBinding`), the abstract it is an alias of, and the deferred
     * provider that provides it, each null when there is none. Nothing is
     * built.
     *
     * @param  class-string  $contract
     * @return array{earlier: (\Closure(mixed ...): mixed)|null, earlierInstance: object|null, earlierAlias: string|null, deferredProvider: string|null}
     */
    private function earlier(string $contract): array
    {
        $deferred = $this->app instanceof FoundationApplication ? $this->app->getDeferredServices()[$contract] ?? null : null;

        return [
            'earlier'          => ContainerState::concrete($this->app, $contract),
            'earlierInstance'  => ContainerState::instance($this->app, $contract),
            'earlierAlias'     => ContainerState::alias($this->app, $contract),
            'deferredProvider' => \is_string($deferred) ? $deferred : null,
        ];
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
