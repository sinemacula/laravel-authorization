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

    /** The contract is an alias of another abstract, which it resolves to. */
    case ALIAS = 'alias';

    /** A binding of a contract the package does not bind itself. */
    case EXTERNAL = 'external_binding';

    /** Nothing is bound to the contract. */
    case UNBOUND = 'unbound';
}
