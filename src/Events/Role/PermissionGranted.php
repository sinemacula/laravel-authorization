<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Role;

use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Dispatched when a permission is attached to a role.
 *
 * Distinct from `Identity\PermissionGranted`, which fires when a permission is
 * attached directly to an authorizable identity. Audit consumers use the event
 * class to distinguish role-catalogue mutations from identity-level grants.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionGranted
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     */
    public function __construct(

        /** Role that received the permission attachment. */
        public Role $role,

        /** Permission that was attached to the role. */
        public Permission $permission,
    ) {}
}
