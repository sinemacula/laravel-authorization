<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics\Enums;

/**
 * Where the binding a seam resolves through came from, as the configuration
 * report tells it without building anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Origin: string
{
    /** The package's default, bound as nothing was bound before it. */
    case PACKAGE_DEFAULT = 'package_default';

    /** The class the configuration names, bound by the package in place of its default. */
    case CONFIGURED = 'configured';

    /** A binding made before the package registered, which the package left standing. */
    case EARLIER_BINDING = 'earlier_binding';

    /** A binding made after the package registered, which replaced the package's. */
    case LATER_BINDING = 'later_binding';

    /** A sibling package's adapter, as it declared it, still bound. */
    case DECLARED = 'declared';

    /** A deferred provider not loaded yet, which binds the contract as it is first resolved. */
    case DEFERRED = 'deferred';

    /** A deferred provider known as the package registered, so the package left it standing, since loaded. */
    case DEFERRED_LOADED = 'deferred_loaded';

    /** The contract is an alias of another abstract, which it resolves to. */
    case ALIAS = 'alias';

    /** A binding of a contract the package does not bind itself. */
    case EXTERNAL = 'external_binding';

    /** Nothing is bound to the contract. */
    case UNBOUND = 'unbound';

    /**
     * Determine whether the binding is the package's own, whose record names
     * the class it builds and the key it forwards to.
     *
     * @return bool
     */
    public function isPackages(): bool
    {
        return $this === self::PACKAGE_DEFAULT || $this === self::CONFIGURED;
    }

    /**
     * Determine whether the binding was made by others, so its closure may be
     * custom code that decides what it builds.
     *
     * @return bool
     */
    public function isOthers(): bool
    {
        return \in_array($this, [self::EARLIER_BINDING, self::LATER_BINDING, self::DEFERRED_LOADED, self::EXTERNAL], true);
    }
}
