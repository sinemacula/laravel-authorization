<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Role;

use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Dispatched after a new role row is persisted.
 *
 * Part of the role-catalogue lifecycle trio (`Created`, `Updated`, `Deleted`)
 * consumed by audit-log sinks responsible for reconstructing the "who created
 * which role when" trail required by SOC 2 / ISO 27001 change-management
 * controls.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Created
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     */
    public function __construct(

        /** Persisted role row. */
        public Role $role,
    ) {}
}
