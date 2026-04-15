<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Dispatched when a permission is attached to a role.
 *
 * Distinct from `PermissionGranted`, which fires when a permission is
 * attached directly to an authorizable identity. Audit consumers use
 * the event class to distinguish role-catalogue mutations from
 * identity-level grants.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RolePermissionGranted
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
