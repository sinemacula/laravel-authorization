<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Identity;

use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Dispatched when a role is revoked from an authorizable identity.
 *
 * Part of the SemVer-stable event API; breaking changes require a
 * major version bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RoleRevoked implements IdentityEvent
{
    /**
     * Create a new event instance.
     *
     * @param  object  $authorizable
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     */
    public function __construct(

        /** Authorizable identity that the role was revoked from. */
        public object $authorizable,

        /** Role that was revoked from the identity. */
        public Role $role,

    ) {}
}
