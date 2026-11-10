<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use Illuminate\Contracts\Container\Container;
use Illuminate\Foundation\Application;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime;

/**
 * What a container holds for a contract at the time the report reads it: the
 * binding's closure, the instance held, how long what it builds lives, the
 * abstract it is an alias of, the deferred provider that will bind it, and
 * whether it was resolved before. Reading it builds nothing (see
 * `ContainerState`).
 *
 * An instance held is what the contract resolves to, as Laravel returns it
 * before anything else, whatever the binding. It is taken for what a shared
 * binding built when the contract was resolved before; any other instance held,
 * over a binding or none, was handed to the container, and supplies the
 * contract itself, its lifetime `instance`. The one rule decides what supplies
 * the contract both as the package records what was bound before it registered
 * and as the report reads it, so the same container state compares equal. An
 * instance handed over a shared binding after the contract was resolved cannot
 * be told from one the binding built, so it is taken for the binding's; its
 * class is still shown, as it is the class the contract resolves to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CurrentBinding
{
    /**
     * Create a new reading of a binding.
     *
     * @param  (\Closure(mixed ...): mixed)|null  $concrete
     * @param  object|null  $instance
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime|null  $lifetime
     * @param  string|null  $alias
     * @param  string|null  $deferredProvider
     * @param  bool  $previouslyResolved
     */
    public function __construct(

        /** The closure the contract is bound to, or null when there is none. */
        public ?\Closure $concrete,

        /** The instance the container holds for the contract, whether a shared binding built it or it was handed over, or null when there is none. */
        public ?object $instance,

        /** How long what the binding builds lives, `instance` for an instance handed to the container, or null when nothing is bound. */
        public ?Lifetime $lifetime,

        /** The abstract the contract is an alias of, or null when it is none. */
        public ?string $alias,

        /** The deferred provider not loaded yet that provides the contract, or null when there is none. */
        public ?string $deferredProvider,

        /** Whether the contract was resolved before, which an instance handed over and never resolved is not, and which says nothing of whether anything is held now. */
        public bool $previouslyResolved,
    ) {}

    /**
     * Read what the container holds for the contract.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $contract
     * @return self
     */
    public static function of(Container $container, string $contract): self
    {
        $deferred = $container instanceof Application && $container->isDeferredService($contract) ? $container->getDeferredServices()[$contract] : null;

        return new self(
            concrete: ContainerState::concrete($container, $contract),
            instance: ContainerState::instance($container, $contract),
            lifetime: self::lifetimeOf($container, $contract),
            alias: ContainerState::alias($container, $contract),
            deferredProvider: \is_string($deferred) ? $deferred : null,
            previouslyResolved: ContainerState::wasResolved($container, $contract),
        );
    }

    /**
     * Return how long what the binding under the key builds lives, `instance`
     * when an instance was handed to the container under it, or null when
     * nothing is bound under it.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $key
     * @return \SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime|null
     */
    public static function lifetimeOf(Container $container, string $key): ?Lifetime
    {
        $isShared = ContainerState::isShared($container, $key);

        // A shared binding resolved before holds what it built as an instance;
        // any other instance held was handed to the container.
        if (ContainerState::instance($container, $key) !== null && !($isShared && ContainerState::wasResolved($container, $key))) {
            return Lifetime::INSTANCE;
        }

        return match (true) {
            ContainerState::concrete($container, $key) === null => null,
            !$isShared                                          => Lifetime::TRANSIENT,
            ContainerState::isScoped($container, $key)          => Lifetime::SCOPED,
            default                                             => Lifetime::SINGLETON,
        };
    }

    /**
     * Return what supplies the contract: the instance handed to the container,
     * or else the binding's closure, which built any instance held.
     *
     * @return object|null
     */
    public function supplier(): ?object
    {
        return $this->lifetime === Lifetime::INSTANCE ? $this->instance : $this->concrete;
    }
}
