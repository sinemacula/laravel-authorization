<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

/**
 * What the package recorded of one seam as it bound it, before binding: whether
 * something was bound to the contract already and what, the closure the package
 * bound, the key it forwards to, the class it builds, and whether a class the
 * configuration names was bound in place of the default.
 *
 * The record is taken once, as the package registers, and never changes. The
 * report compares the contract's binding at the time it runs with the objects
 * recorded here, by identity, to tell the package's binding from one made
 * before it registered and one made after.
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
     * @param  object|null  $earlier
     * @param  string|null  $earlierAlias
     * @param  string|null  $deferredProvider
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

        /** The binding's closure or the instance the contract held before the package registered, else null. */
        public ?object $earlier,

        /** The abstract the contract was an alias of before the package registered, else null. */
        public ?string $earlierAlias,

        /** The deferred provider that provided the contract as the package registered, else null. */
        public ?string $deferredProvider,
    ) {}

    /**
     * Determine whether something was bound to the contract before the package
     * registered.
     *
     * @return bool
     */
    public function wasBound(): bool
    {
        return $this->earlier !== null || $this->earlierAlias !== null;
    }
}
