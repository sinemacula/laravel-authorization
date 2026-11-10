<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Registrars;

use Illuminate\Container\Container as BaseContainer;
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
 * Handed the steps the package leaves to the application's boot (see
 * `PendingRegistration`), as the service provider hands them, the registrar
 * binds only the package's defaults at once. It records the binding of a class
 * the configuration names, which autoloads the class, may load a deferred
 * provider and calls the callbacks watching the contract, and the extending of
 * the grant hook, which applies at once to an instance held, as steps to run as
 * the application boots, after every provider registered, keeping the name the
 * configuration gives as a string until then. The outcome is the one binding
 * them at once gave: a class configured is bound over what was bound before the
 * package registered and over a deferred provider's binding, a binding made
 * after the package registered stands, the record keeps what was bound before
 * the package registered, and the configured hooks' extender keeps its place
 * among the contract's extenders. What a provider resolves while it registers
 * is the package's default, the class configured being bound only as the
 * application boots. Handed none, as a test may build it, it runs each step at
 * once.
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
     * @param  \SineMacula\Laravel\Authorization\Registrars\PendingRegistration|null  $later
     */
    public function __construct(

        /** The application the seams are bound in. */
        private Application $app,

        /** Build the closure a contract is bound to, resolving the package-owned key given; the service provider declares both. */
        private \Closure $resolving,

        /** The steps left to the application's boot, or null to run each at once. */
        private ?PendingRegistration $later = null,
    ) {}

    /**
     * Bind a contract to the class the configuration key names, the package's
     * default when it names none, built once per request or job, or bind
     * nothing when there is no default and it names none.
     *
     * A class other than the package's default is the application's explicit
     * choice, so it replaces a binding a sibling package made before the
     * package registers (N106); the package's default gives way to one. The
     * concrete bound is the class, or what the builder given makes of it.
     *
     * @param  class-string  $contract
     * @param  string  $key
     * @param  class-string|null  $default
     * @param  (\Closure(class-string): (class-string|\Closure(\Illuminate\Contracts\Foundation\Application): object))|null  $build
     * @return void
     */
    public function bindConfigured(string $contract, string $key, ?string $default, ?\Closure $build = null): void
    {
        $build ??= self::itself(...);

        if ($this->later !== null) {
            $this->bindConfiguredLater($this->later, $contract, $key, $default, $build);

            return;
        }

        $class = $this->configuredClass($key, $contract, $default);

        if ($class === null) {
            return;
        }

        if ($default !== null && ClassName::areSame($class, $default)) {
            $this->bindDefault($contract, $build($default), false, $key, $default);

            return;
        }

        $this->bindDefault($contract, $build($class), true, $key, $class);
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

        return self::implements($class, $contract) ? $class : $default;
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
     * may resolve the configured class as it is bound.
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
        return $this->bind($contract, $concrete, $configured, $configKey, $builds, $this->earlier($contract));
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

        if ($this->later === null) {
            $this->extendGrantHooks($record);

            return;
        }

        $position = \count(ContainerState::extenders($this->app, GrantHook::class));

        $this->later->later(function () use ($record, $position): void {
            $this->extendGrantHooks($record, $position);
        });
    }

    /**
     * Return the class given, the concrete a configured class is bound to when
     * no builder is given.
     *
     * @param  class-string  $class
     * @return class-string
     */
    private static function itself(string $class): string
    {
        return $class;
    }

    /**
     * Determine whether the value names an existing class implementing the
     * contract, autoloading it.
     *
     * @param  mixed  $class
     * @param  string  $contract
     * @return bool
     *
     * @phpstan-assert-if-true class-string $class
     */
    private static function implements(mixed $class, string $contract): bool
    {
        return \is_string($class) && $class !== '' && \class_exists($class) && \is_a($class, $contract, true);
    }

    /**
     * Bind the package's default now, when there is one, and record the binding
     * of the class the configuration names in its place as a step to run as the
     * application boots, keeping the name as the configuration gives it.
     *
     * When the configuration names a class other than the default, the contract
     * is bound now, when nothing is bound to it yet, through a closure this
     * class declares, not the provider, so a sibling package reading the
     * binding table leaves it to the application's choice, as it left the class
     * bound at once; it resolves the default until the step runs.
     *
     * The step binds only when the contract is bound as it was when the package
     * registered, so a binding made after the package registered stands, as it
     * did over a class bound at once, a deferred provider of the contract being
     * loaded beneath it, as binding the class at once loaded it. It binds the
     * class when it exists and implements the contract, recording what was
     * bound before the package registered as it was then; otherwise it binds
     * the default as when nothing is configured, for the boot to refuse the
     * setting.
     *
     * @param  \SineMacula\Laravel\Authorization\Registrars\PendingRegistration  $later
     * @param  class-string  $contract
     * @param  string  $key
     * @param  class-string|null  $default
     * @param  \Closure(class-string): (class-string|\Closure(\Illuminate\Contracts\Foundation\Application): object)  $build
     * @return void
     */
    private function bindConfiguredLater(PendingRegistration $later, string $contract, string $key, ?string $default, \Closure $build): void
    {
        $named = $this->namedInPlaceOf($key, $default);

        if ($named === null) {
            if ($default !== null) {
                $this->bindDefault($contract, $build($default), false, $key, $default);
            }

            return;
        }

        $earlier = $this->earlier($contract);
        $target  = self::DEFAULT_BINDING_PREFIX . $contract;
        $chosen  = static fn (Application $app): mixed => $app->make($target);

        $this->record(new SeamRecord($contract, $chosen, $target, $default, $key, false, ...$earlier));

        if ($default !== null) {
            $this->app->scoped($target, $build($default));
        }

        $this->app->bindIf($contract, $chosen);

        $registered = $this->bindingOf($contract);

        $later->later(function () use ($contract, $key, $named, $default, $build, $earlier, $chosen, $registered): void {
            $isUnchanged = $this->bindingOf($contract) === $registered;
            $isValid     = self::implements($named, $contract);

            if ($isUnchanged && $isValid) {
                $this->bind($contract, $build($named), true, $key, $named, $earlier);
            } elseif ($isUnchanged) {
                $this->bindDefaultOver($contract, $chosen, $key, $default, $earlier);
            } elseif ($isValid) {
                $this->keepLaterBinding($contract, $chosen, $build($named), $key, $named, $earlier);
            }
        });
    }

    /**
     * Return the name the configuration key gives when it names a class other
     * than the default, as it gives it, without loading anything, or null when
     * it gives no such name.
     *
     * @param  string  $key
     * @param  string|null  $default
     * @return string|null
     */
    private function namedInPlaceOf(string $key, ?string $default): ?string
    {
        $named = $this->app['config']->get($key, $default);

        return \is_string($named) && $named !== '' && ($default === null || !ClassName::areSame($named, $default)) ? $named : null;
    }

    /**
     * Bind the contract as when the configuration names no class for it, in
     * place of the closure bound for the class it named, when it is still bound
     * to that closure: to the package's default, or to nothing when there is
     * none.
     *
     * @param  class-string  $contract
     * @param  \Closure(\Illuminate\Contracts\Foundation\Application): mixed  $chosen
     * @param  string  $key
     * @param  class-string|null  $default
     * @param  array{earlier: (\Closure(mixed ...): mixed)|null, earlierInstance: object|null, earlierAlias: string|null, deferredProvider: string|null}  $earlier
     * @return void
     */
    private function bindDefaultOver(string $contract, \Closure $chosen, string $key, ?string $default, array $earlier): void
    {
        if (ContainerState::concrete($this->app, $contract) !== $chosen) {
            return;
        }

        if ($default === null) {
            $app = $this->app;

            unset($app[$contract]);
            BindingRegistry::of($this->app)->forget($contract);

            return;
        }

        $target  = self::DEFAULT_BINDING_PREFIX . $contract;
        $binding = ($this->resolving)($target);

        $this->record(new SeamRecord($contract, $binding, $target, $default, $key, false, ...$earlier));

        $this->app->bind($contract, $binding);
    }

    /**
     * Do what binding the class the configuration names as the package
     * registered did, short of binding the contract, which a binding made after
     * the package registered replaced: record the class as bound, hold it under
     * the package-owned key and load the deferred provider of the contract,
     * when one is still deferred, keeping that later binding over the one the
     * provider makes.
     *
     * @param  class-string  $contract
     * @param  \Closure(\Illuminate\Contracts\Foundation\Application): mixed  $chosen
     * @param  class-string|\Closure(\Illuminate\Contracts\Foundation\Application): object  $concrete
     * @param  string  $key
     * @param  class-string  $class
     * @param  array{earlier: (\Closure(mixed ...): mixed)|null, earlierInstance: object|null, earlierAlias: string|null, deferredProvider: string|null}  $earlier
     * @return void
     */
    private function keepLaterBinding(string $contract, \Closure $chosen, \Closure|string $concrete, string $key, string $class, array $earlier): void
    {
        $app    = $this->app;
        $target = self::DEFAULT_BINDING_PREFIX . $contract;

        $this->record(new SeamRecord($contract, $chosen, $target, $class, $key, true, ...$earlier));

        $app->scoped($target, $concrete);

        if (!$app instanceof FoundationApplication || !$app->isDeferredService($contract)) {
            return;
        }

        $binding  = $app->getBindings()[$contract] ?? null;
        $instance = ContainerState::instance($app, $contract);
        $alias    = ContainerState::alias($app, $contract);

        $app->loadDeferredProvider($contract);

        match (true) {
            $instance !== null => $app->instance($contract, $instance),
            $alias    !== null => $app->alias($alias, $contract),
            $binding  !== null => $app->bind($contract, $binding['concrete'], $binding['shared']),
            default            => null,
        };
    }

    /**
     * Extend the grant hook so the hooks the configuration lists run before
     * whatever it resolves to, recording the decorator that replaced an
     * instance held, and, given where the package registered its extender among
     * the contract's, place it there, before any registered after it.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord  $record
     * @param  int|null  $position
     * @return void
     */
    private function extendGrantHooks(SeamRecord $record, ?int $position = null): void
    {
        $held = ContainerState::instance($this->app, GrantHook::class);

        $this->app->extend(GrantHook::class, ListedGrantHooks::around(...));

        // Laravel applies the extender at once to an instance it holds and
        // keeps no trace of it, so the decorator that replaced the instance is
        // recorded, for the report to tell it from a later binding.
        $wrapper = ContainerState::instance($this->app, GrantHook::class);

        if ($held === null && $position !== null) {
            $this->placeLastExtender(GrantHook::class, $position);
        }

        if ($wrapper === $held) {
            return;
        }

        $this->record($record->wrappedBy($wrapper));
    }

    /**
     * Move the extender registered last on the abstract to the position given
     * among its extenders.
     *
     * @param  string  $abstract
     * @param  int  $position
     * @return void
     */
    private function placeLastExtender(string $abstract, int $position): void
    {
        if (!$this->app instanceof BaseContainer) {
            return;
        }

        \Closure::bind(static function (BaseContainer $container) use ($abstract, $position): void {
            $alias     = $container->getAlias($abstract);
            $extenders = $container->extenders[$alias] ?? [];
            $last      = \array_splice($extenders, -1);

            \array_splice($extenders, $position, 0, $last);

            $container->extenders[$alias] = $extenders;
        }, null, BaseContainer::class)($this->app);
    }

    /**
     * Return what the contract is bound to now: the binding's closure, the
     * instance held and the abstract it is an alias of. Nothing is built.
     *
     * @param  string  $contract
     * @return array{(\Closure(mixed ...): mixed)|null, object|null, string|null}
     */
    private function bindingOf(string $contract): array
    {
        return [ContainerState::concrete($this->app, $contract), ContainerState::instance($this->app, $contract), ContainerState::alias($this->app, $contract)];
    }

    /**
     * Bind the contract as `bindDefault()` describes, recording what was bound
     * to it before as given.
     *
     * @param  class-string  $contract
     * @param  class-string|\Closure(\Illuminate\Contracts\Foundation\Application): object  $concrete
     * @param  bool  $configured
     * @param  string|null  $configKey
     * @param  class-string|null  $builds
     * @param  array{earlier: (\Closure(mixed ...): mixed)|null, earlierInstance: object|null, earlierAlias: string|null, deferredProvider: string|null}  $earlier
     * @return \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord
     */
    private function bind(string $contract, \Closure|string $concrete, bool $configured, ?string $configKey, ?string $builds, array $earlier): SeamRecord
    {
        $default = self::DEFAULT_BINDING_PREFIX . $contract;

        // The application's own choice is bound through a closure this class
        // declares, not the provider, so neither the provider's
        // isPackageDefault() nor a sibling reading the binding table takes it
        // for the package's default and replaces it.
        $binding = $configured
            ? static fn (Application $app): mixed => $app->make($default)
            : ($this->resolving)($default);

        $record = new SeamRecord($contract, $binding, $default, \is_string($concrete) ? $concrete : $builds, $configKey, $configured, ...$earlier);

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
