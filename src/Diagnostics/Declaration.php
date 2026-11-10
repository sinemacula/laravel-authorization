<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime;

/**
 * What a sibling package declared of a contract it binds: its name, the class
 * its adapter is, or the classes a factory may build and when it decides, how
 * long what it builds lives, and, optionally, the exact closure it bound.
 *
 * A declaration is data only: no class it names is loaded or built. It is
 * authoritative only while the closure it names is still what the contract is
 * bound to, compared by identity; without one, or once another binding has
 * replaced it, the report shows the declaration beside what is bound instead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Declaration
{
    /**
     * Create a new declaration.
     *
     * @param  string  $contract
     * @param  string  $owner
     * @param  list<string>  $classes
     * @param  string|null  $decides
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime  $lifetime
     * @param  (\Closure(never): mixed)|null  $binding
     */
    public function __construct(

        /** The contract the sibling binds. */
        public string $contract,

        /** The name of the sibling that binds it. */
        public string $owner,

        /** The class the adapter is, or the classes the factory may build. */
        public array $classes,

        /** When a factory decides which class it builds, or null for an adapter of one class. */
        public ?string $decides,

        /** How long what the binding builds lives. */
        public Lifetime $lifetime,

        /** The closure the sibling bound to the contract, or null when it named none. */
        public ?\Closure $binding,
    ) {}

    /**
     * Determine whether the declaration is of a factory, which decides among
     * its classes when it is resolved.
     *
     * @return bool
     */
    public function isFactory(): bool
    {
        return $this->decides !== null;
    }

    /**
     * Return whether the declaration still describes the contract's binding:
     * `standing` while the closure it names is bound, `overridden` once another
     * binding replaced it, or `unverified` when it names no closure.
     *
     * @param  (\Closure(mixed ...): mixed)|null  $concrete
     * @return string
     */
    public function standing(?\Closure $concrete): string
    {
        return match (true) {
            $this->binding === null      => 'unverified',
            $this->binding === $concrete => 'standing',
            default                      => 'overridden',
        };
    }
}
