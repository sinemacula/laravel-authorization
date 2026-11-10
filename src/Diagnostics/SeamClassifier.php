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
 * What the container holds for the contract now (see `CurrentBinding`) is
 * compared by identity with what the package recorded as it bound the contract
 * (see `BindingRegistry`) and with what a sibling package declared (see
 * `Declarations`):
 *
 * - an alias, or a deferred provider not loaded yet, is shown as such;
 * - a sibling's declared closure still bound is the sibling's adapter;
 * - the package's own closure is its default, or the configured class;
 * - the binding held before the package registered is an earlier binding;
 * - anything else is a later binding.
 *
 * The class is read without building: the package's record, a sibling's
 * declaration, the class of an instance already held, or the class a binding
 * made with a class name holds. A closure that names none is custom code whose
 * class is decided at first use, shown by where it is written; it never makes
 * the check fail. How long what the seam builds lives is read from the binding
 * the package's closure forwards to, not from the closure itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SeamClassifier
{
    /** @var list<\SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin> The origins of a binding made by others, whose closure may decide what it builds. */
    private const array BOUND_BY_OTHERS = [Origin::EARLIER_BINDING, Origin::LATER_BINDING, Origin::EXTERNAL];

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
        $origin      = self::origin($binding, $record, $declaration);
        $classes     = $this->classes($origin, $binding, $record, $declaration);

        return new SeamRow(
            contract: $contract,
            origin: $origin,
            classes: $classes,
            factory: $classes === [] && $binding->instance === null && \in_array($origin, self::BOUND_BY_OTHERS, true) ? $this->location($binding->concrete) : null,
            lifetime: $this->lifetime($origin, $binding, $record, $declaration),
            extenders: \array_map($this->extender(...), ContainerState::extenders($this->container, $contract)),
            binding: $binding,
            record: $record,
            declaration: $declaration,
        );
    }

    /**
     * Return where the binding came from.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\CurrentBinding  $binding
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord|null  $record
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Declaration|null  $declaration
     * @return \SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin
     */
    private static function origin(CurrentBinding $binding, ?SeamRecord $record, ?Declaration $declaration): Origin
    {
        return match (true) {
            $binding->alias            !== null                                                       => Origin::ALIAS,
            $binding->deferredProvider !== null                                                       => Origin::DEFERRED,
            $binding->supplier()                        === null                                      => Origin::UNBOUND,
            $declaration?->standing($binding->concrete) === 'standing' && $binding->instance === null => Origin::DECLARED,
            $record                                     === null                                      => Origin::EXTERNAL,
            default                                                                                   => self::recorded($binding, $record),
        };
    }

    /**
     * Return where the binding of a seam the package recorded came from, by
     * comparing what supplies it with the objects recorded.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\CurrentBinding  $binding
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord  $record
     * @return \SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin
     */
    private static function recorded(CurrentBinding $binding, SeamRecord $record): Origin
    {
        $supplier = $binding->supplier();

        return match (true) {
            $supplier === $record->binding => $record->configured ? Origin::CONFIGURED : Origin::PACKAGE_DEFAULT,
            $supplier === $record->earlier => Origin::EARLIER_BINDING,
            default                        => Origin::LATER_BINDING,
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
        $class = match ($origin) {
            Origin::PACKAGE_DEFAULT, Origin::CONFIGURED => $record?->class,
            Origin::DECLARED                            => null,
            Origin::ALIAS                               => $binding->alias,
            Origin::DEFERRED, Origin::UNBOUND           => null,
            default                                     => $binding->instance !== null ? $binding->instance::class : self::boundClass($binding->concrete),
        };

        if ($origin === Origin::DECLARED && $declaration !== null) {
            return $declaration->classes;
        }

        return $class === null ? [] : [$class];
    }

    /**
     * Return how long what the seam builds lives: what a sibling declared for
     * its adapter, that of the key the package's closure forwards to, or that
     * of the binding itself.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin  $origin
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\CurrentBinding  $binding
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord|null  $record
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Declaration|null  $declaration
     * @return \SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime|null
     */
    private function lifetime(Origin $origin, CurrentBinding $binding, ?SeamRecord $record, ?Declaration $declaration): ?Lifetime
    {
        $target = match ($origin) {
            Origin::PACKAGE_DEFAULT, Origin::CONFIGURED => $record?->target,
            Origin::ALIAS                               => $binding->alias,
            default                                     => null,
        };

        return match (true) {
            $origin === Origin::DECLARED => $declaration?->lifetime,
            $target !== null             => CurrentBinding::lifetimeOf($this->container, $target),
            default                      => $binding->lifetime,
        };
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

        if ($closure->getName() === 'around' && $closure->getClosureScopeClass()?->getName() === ListedGrantHooks::class) {
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
