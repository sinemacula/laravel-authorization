<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

/**
 * What the package recorded of one seam as it bound it, before binding: whether
 * something was bound to the contract already and what, the closure the package
 * bound, the key it forwards to, the class it builds, whether a class the
 * configuration names was bound in place of the default, and, for the grant
 * hook, the decorator running the configured hooks that replaced an instance
 * held at once.
 *
 * The record is taken as the package binds the seam, as it registers, or, for a
 * class the configuration names, as the application boots, when it is bound,
 * still recording what was bound before the package registered, and never
 * changes. The report compares what supplies the contract at the time it runs
 * (see `CurrentBinding::supplier()`) with the objects recorded here, by
 * identity, to tell the package's binding from one made before it registered
 * and one made after: both the closure and the instance held before are
 * recorded, and either matches.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SeamRecord
{
    /**
     * Create a new record.
     *
     * @param  string  $contract
     * @param  \Closure(\Illuminate\Contracts\Foundation\Application): mixed  $binding
     * @param  string|null  $target
     * @param  string|null  $class
     * @param  string|null  $configKey
     * @param  bool  $configured
     * @param  (\Closure(mixed ...): mixed)|null  $earlier
     * @param  object|null  $earlierInstance
     * @param  string|null  $earlierAlias
     * @param  string|null  $deferredProvider
     * @param  object|null  $wrapper
     */
    public function __construct(

        /** The contract bound. */
        public string $contract,

        /** The closure the package bound to the contract, or would have bound had nothing been bound before. */
        public \Closure $binding,

        /** The key the binding forwards to, whose binding decides how long what it builds lives, or null when it forwards to none. */
        public ?string $target,

        /** The class the package's binding builds, when it is known without building it. */
        public ?string $class,

        /** The configuration key naming the class, or null when the seam has none. */
        public ?string $configKey,

        /** Whether the class the configuration names was bound in place of the package's default. */
        public bool $configured,

        /** The closure the contract was bound to before the package registered, else null. */
        public ?\Closure $earlier,

        /** The instance the container held for the contract before the package registered, else null. */
        public ?object $earlierInstance,

        /** The abstract the contract was an alias of before the package registered, else null. */
        public ?string $earlierAlias,

        /** The deferred provider that provided the contract as the package registered, else null. */
        public ?string $deferredProvider,

        /** The decorator running the configured grant hooks that replaced the instance held as the package registered, else null. */
        public ?object $wrapper = null,
    ) {}

    /**
     * Return the record with the decorator that replaced the instance held as
     * the package registered.
     *
     * @param  object|null  $wrapper
     * @return self
     */
    public function wrappedBy(?object $wrapper): self
    {
        return new self(
            $this->contract,
            $this->binding,
            $this->target,
            $this->class,
            $this->configKey,
            $this->configured,
            $this->earlier,
            $this->earlierInstance,
            $this->earlierAlias,
            $this->deferredProvider,
            $wrapper,
        );
    }

    /**
     * Determine whether something was bound to the contract before the package
     * registered.
     *
     * @return bool
     */
    public function wasBound(): bool
    {
        return $this->earlier !== null || $this->earlierInstance !== null || $this->earlierAlias !== null;
    }

    /**
     * Determine whether what supplies the contract now was bound before the
     * package registered: the closure or the instance held then, or the
     * decorator that replaced that instance at once.
     *
     * @param  object|null  $supplier
     * @return bool
     */
    public function isEarlier(?object $supplier): bool
    {
        return $supplier !== null && \in_array($supplier, [$this->earlier, $this->earlierInstance, $this->wrapper], true);
    }

    /**
     * Return the instance held as it is shown: the instance held before the
     * package registered in place of the decorator that replaced it, any other
     * as it is.
     *
     * @param  object|null  $instance
     * @return object|null
     */
    public function unwrap(?object $instance): ?object
    {
        return $instance !== null && $instance === $this->wrapper ? $this->earlierInstance : $instance;
    }
}
