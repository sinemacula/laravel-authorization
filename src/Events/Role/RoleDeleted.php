<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Role;

use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Dispatched after a role row is deleted.
 *
 * Carries the final snapshot of the row so audit consumers can
 * persist the deleted entity's last-known state before the source
 * row disappears.
 *
 * Part of the SemVer-stable event API; breaking changes require a
 * major version bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RoleDeleted
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     */
    public function __construct(

        /** Role row captured immediately after deletion. */
        public Role $role,

    ) {}
}
