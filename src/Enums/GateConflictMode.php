<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Enums;

/**
 * Gate-registration conflict policy.
 *
 * Drives the three behaviours the service provider can take when a Gate already
 * exists for a permission the enum walker is about to register. Backed by
 * strings so consumers configure the policy with a human-readable sentinel in
 * `config/authorization.php` while the service provider and validator consume a
 * type-checked enum value instead of a stringly-typed `match`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum GateConflictMode: string
{
    /**
     * Emit a warning and preserve the existing Gate.
     */
    case LOG = 'log';

    /**
     * Raise a typed `GateConflictException`.
     */
    case THROW = 'throw';

    /**
     * Replace the existing Gate with the package-registered one.
     */
    case OVERWRITE = 'overwrite';
}
