<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use Illuminate\Contracts\Container\Container;
use Illuminate\Foundation\Application;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime;

/**
 * What a container holds for a contract at the time the report reads it: the
 * binding's closure, an instance handed to it, how long what it builds lives,
 * the abstract it is an alias of, the deferred provider that will bind it, and
 * whether it was resolved before. Reading it builds nothing (see
 * `ContainerState`).
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

        /** The instance handed to the container for the contract, or null when there is none. */
        public ?object $instance,

        /** How long what the binding builds lives, or null when nothing is bound. */
        public ?Lifetime $lifetime,

        /** The abstract the contract is an alias of, or null when it is none. */
        public ?string $alias,

        /** The deferred provider not loaded yet that provides the contract, or null when there is none. */
        public ?string $deferredProvider,

        /** Whether the contract was resolved before, which says nothing of whether anything is held now. */
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
        $concrete = ContainerState::concrete($container, $contract);
        $isShared = ContainerState::isShared($container, $contract);

        // A shared binding keeps what it built as an instance, which is not one
        // handed to the container; an instance over a binding that is not
        // shared was handed to it.
        $instance = $concrete !== null                && $isShared ? null : ContainerState::instance($container, $contract);
        $deferred = $container instanceof Application && $container->isDeferredService($contract) ? $container->getDeferredServices()[$contract] : null;

        return new self(
            concrete: $concrete,
            instance: $instance,
            lifetime: $instance !== null ? Lifetime::INSTANCE : self::lifetimeOf($container, $contract),
            alias: ContainerState::alias($container, $contract),
            deferredProvider: \is_string($deferred) ? $deferred : null,
            previouslyResolved: $container->resolved($contract),
        );
    }

    /**
     * Return how long what the binding under the key builds lives, or null when
     * nothing is bound under it.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $key
     * @return \SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime|null
     */
    public static function lifetimeOf(Container $container, string $key): ?Lifetime
    {
        if (ContainerState::concrete($container, $key) === null) {
            return ContainerState::instance($container, $key) === null ? null : Lifetime::INSTANCE;
        }

        return match (true) {
            !ContainerState::isShared($container, $key) => Lifetime::TRANSIENT,
            ContainerState::isScoped($container, $key)  => Lifetime::SCOPED,
            default                                     => Lifetime::SINGLETON,
        };
    }

    /**
     * Return what supplies the contract: the instance handed to the container,
     * or else the binding's closure.
     *
     * @return object|null
     */
    public function supplier(): ?object
    {
        return $this->instance ?? $this->concrete;
    }
}
