<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use Illuminate\Container\Container as IlluminateContainer;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Config\GrantHookConfigValidator;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin;
use SineMacula\Laravel\Authorization\Hooks\ListedGrantHooks;

/**
 * Tell where each seam's binding came from without building it (N113, N118).
 *
 * What supplies the contract now (see `CurrentBinding`) is compared by identity
 * with what the package recorded as it bound the contract (see
 * `BindingRegistry`) and with what a sibling package declared (see
 * `Declarations`):
 *
 * - an alias, or a deferred provider not loaded yet, is shown as such;
 * - a sibling's declared closure still bound, with no instance handed over it,
 *   is the sibling's adapter;
 * - the package's own closure is its default, or the configured class;
 * - the closure or the instance held before the package registered is an
 *   earlier binding, and so is the decorator running the configured grant hooks
 *   that replaced such an instance, shown by the instance it decorates; one
 *   that replaced an instance handed the container after the package registered
 *   is a later binding, shown by that instance too;
 * - whatever binds the contract once a deferred provider the package left
 *   standing as it registered has loaded is that provider's binding;
 * - anything else is a later binding.
 *
 * The class is read without building: a sibling's declaration, the class of an
 * instance held, which is what the contract resolves to, the package's record,
 * or the class a binding made with a class name holds. A closure that names
 * none is custom code whose class is decided at first use, shown by where it is
 * written; it never makes the check fail. How long what the seam builds lives
 * is read from the binding the package's closure forwards to, not from the
 * closure itself, and a binding made with a class name is followed to the
 * class's own binding: what it builds lives as long as the longer of the two.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SeamClassifier
{
    /** @var string How the configured grant hooks applied to the instance held as the application booted are shown among the extenders. */
    public const string APPLIED = GrantHookConfigValidator::KEY . ' (applied to the held instance)';

    /**
     * Create a new classifier.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\BindingRegistry  $registry
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Declarations  $declarations
     * @param  string|null  $basePath
     */
    public function __construct(

        /** The container the seams are bound in. */
        private Container $container,

        /** What the package recorded as it bound each seam. */
        private BindingRegistry $registry,

        /** What sibling packages declared of the seams they bind. */
        private Declarations $declarations,

        /** The application's base path, which the files closures are written in are shown relative to, or null to show them whole. */
        private ?string $basePath = null,
    ) {}

    /**
     * Return the seam bound to the contract, as the report shows it.
     *
     * @param  string  $contract
     * @return \SineMacula\Laravel\Authorization\Diagnostics\SeamRow
     */
    public function classify(string $contract): SeamRow
    {
        $binding     = CurrentBinding::of($this->container, $contract);
        $record      = $this->registry->get($contract);
        $declaration = $this->declarations->for($contract);
        $extenders   = \array_map($this->extender(...), ContainerState::extenders($this->container, $contract));

        [$origin, $source] = self::origin($binding, $record, $declaration);

        $classes = $this->classes($origin, $binding, $record, $declaration);

        return new SeamRow(
            contract: $contract,
            origin: $origin,
            classes: $classes,
            factory: $classes === [] && $origin->isOthers() ? $this->location($binding->concrete) : null,
            lifetime: $this->lifetime($contract, $origin, $binding, $record, $declaration),
            extenders: $record !== null && $record->unwrap($binding->instance) !== $binding->instance ? [self::APPLIED, ...$extenders] : $extenders,
            binding: $binding,
            record: $record,
            declaration: $declaration,
            source: $source,
        );
    }

    /**
     * Return where the binding came from, and what that names: the setting
     * naming the configured class, the sibling that declared it, the deferred
     * provider or the abstract an alias names; null when it names nothing.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\CurrentBinding  $binding
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord|null  $record
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Declaration|null  $declaration
     * @return array{\SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin, string|null}
     */
    private static function origin(CurrentBinding $binding, ?SeamRecord $record, ?Declaration $declaration): array
    {
        return match (true) {
            $binding->alias            !== null                                      => [Origin::ALIAS, $binding->alias],
            $binding->deferredProvider !== null                                      => [Origin::DEFERRED, $binding->deferredProvider],
            $binding->supplier()                                      === null       => [Origin::UNBOUND, null],
            $declaration !== null && $declaration->standing($binding) === 'standing' => [Origin::DECLARED, $declaration->owner],
            $record                                                   === null       => [Origin::EXTERNAL, null],
            default                                                                  => self::recorded($binding, $record),
        };
    }

    /**
     * Return where the binding of a seam the package recorded came from, by
     * comparing what supplies it with the objects recorded, and what that
     * names.
     *
     * A deferred provider known as the package registered made the package
     * leave the contract to it, so whatever binds the contract once it loaded,
     * other than the package, is taken for the provider's.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\CurrentBinding  $binding
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord  $record
     * @return array{\SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin, string|null}
     */
    private static function recorded(CurrentBinding $binding, SeamRecord $record): array
    {
        $supplier = $binding->supplier();

        return match (true) {
            $supplier === $record->binding                             => $record->configured ? [Origin::CONFIGURED, $record->configKey] : [Origin::PACKAGE_DEFAULT, null],
            $record->isEarlier($supplier)                              => [Origin::EARLIER_BINDING, null],
            $record->deferredProvider !== null && !$record->configured => [Origin::DEFERRED_LOADED, $record->deferredProvider],
            default                                                    => [Origin::LATER_BINDING, null],
        };
    }

    /**
     * Return the class the seam builds, or the classes a declared factory may
     * build, when known without building them; none otherwise.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin  $origin
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\CurrentBinding  $binding
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord|null  $record
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Declaration|null  $declaration
     * @return list<string>
     */
    private function classes(Origin $origin, CurrentBinding $binding, ?SeamRecord $record, ?Declaration $declaration): array
    {
        if ($origin === Origin::DECLARED && $declaration !== null) {
            return $declaration->classes;
        }

        $instance = $record === null ? $binding->instance : $record->unwrap($binding->instance);

        $class = match (true) {
            $binding->alias !== null                    => $binding->alias,
            $origin === Origin::DEFERRED                => null,
            $instance !== null                          => $instance::class,
            $record   !== null && $origin->isPackages() => $record->class,
            default                                     => self::boundClass($binding->concrete),
        };

        return $class === null ? [] : [$class];
    }

    /**
     * Return how long what the seam builds lives: what a sibling declared for
     * its adapter, or that of the key the binding resolves through, the
     * package's closure's own key, the abstract an alias names, or the
     * contract, followed to the bindings of the classes it forwards to.
     *
     * @param  string  $contract
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin  $origin
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\CurrentBinding  $binding
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord|null  $record
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Declaration|null  $declaration
     * @return \SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime|null
     */
    private function lifetime(string $contract, Origin $origin, CurrentBinding $binding, ?SeamRecord $record, ?Declaration $declaration): ?Lifetime
    {
        if ($origin === Origin::DECLARED && $declaration !== null) {
            return $declaration->lifetime;
        }

        $key = match (true) {
            $binding->alias !== null                          => $binding->alias,
            $record         !== null && $origin->isPackages() => $record->target ?? $contract,
            default                                           => $contract,
        };

        $lifetime = CurrentBinding::lifetimeOf($this->container, $key);

        return $lifetime === null ? null : $this->forwarded($key, $lifetime);
    }

    /**
     * Return how long what the key builds lives, following each class its
     * binding names to the class's own binding: the longer of the lifetimes
     * met, as whichever keeps what it built hands it back. A class with no
     * binding of its own is built afresh, which changes nothing.
     *
     * @param  string  $key
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime  $lifetime
     * @return \SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime
     */
    private function forwarded(string $key, Lifetime $lifetime): Lifetime
    {
        $seen = [$key];

        for ($next = $this->forwardsTo($key); $next !== null && !\in_array($next, $seen, true); $next = $this->forwardsTo($next)) {
            $seen[]   = $next;
            $further  = CurrentBinding::lifetimeOf($this->container, $next);
            $lifetime = $further?->outlives($lifetime) === true ? $further : $lifetime;
        }

        return $lifetime;
    }

    /**
     * Return the abstract the binding under the key forwards to, when it was
     * made with a class name, after any alias is followed, or null.
     *
     * @param  string  $key
     * @return string|null
     */
    private function forwardsTo(string $key): ?string
    {
        $class = self::boundClass(ContainerState::concrete($this->container, $key));

        return $class === null ? null : ContainerState::alias($this->container, $class) ?? $class;
    }

    /**
     * Return the class a binding made with a class name holds, read from the
     * closure Laravel wraps it in, or null for any other closure.
     *
     * @param  (\Closure(mixed ...): mixed)|null  $concrete
     * @return string|null
     */
    private static function boundClass(?\Closure $concrete): ?string
    {
        if ($concrete === null) {
            return null;
        }

        $closure = new \ReflectionFunction($concrete);
        $class   = $closure->getClosureUsedVariables()['concrete'] ?? null;

        return $closure->getClosureScopeClass()?->getName() === IlluminateContainer::class && \is_string($class) ? $class : null;
    }

    /**
     * Return how an extender is shown: the package's, which runs the hooks the
     * configuration lists, by that setting; any other by where it is written.
     *
     * @param  \Closure(mixed ...): mixed  $extender
     * @return string
     */
    private function extender(\Closure $extender): string
    {
        $closure = new \ReflectionFunction($extender);

        if ($closure->getClosureScopeClass()?->getName() === ListedGrantHooks::class && $closure->getName() === 'around') {
            return GrantHookConfigValidator::KEY;
        }

        return $this->location($extender) ?? 'unknown';
    }

    /**
     * Return where the closure is written, as a file relative to the base path
     * and a line, or null for none.
     *
     * @param  (\Closure(mixed ...): mixed)|null  $closure
     * @return string|null
     */
    private function location(?\Closure $closure): ?string
    {
        if ($closure === null) {
            return null;
        }

        $function = new \ReflectionFunction($closure);
        $file     = (string) $function->getFileName();
        $base     = $this->basePath === null ? '' : \rtrim($this->basePath, '/') . '/';

        if ($base !== '/' && \str_starts_with($file, $base)) {
            $file = \substr($file, \strlen($base));
        }

        return "{$file}:{$function->getStartLine()}";
    }
}
