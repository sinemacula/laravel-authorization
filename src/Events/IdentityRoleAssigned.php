<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Dispatched when a role is assigned to an authorizable identity.
 *
 * Part of the SemVer-stable event API; breaking changes require a
 * major version bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentityRoleAssigned
{
    /**
     * Create a new event instance.
     *
     * @param  object  $authorizable
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     */
    public function __construct(

        /** Authorizable identity that received the role assignment. */
        public object $authorizable,

        /** Role that was assigned to the identity. */
        public Role $role,

    ) {}
}
