<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Role;

use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Dispatched when a permission is detached from a role.
 *
 * Distinct from `IdentityPermissionRevoked`, which fires when a direct
 * permission grant is removed from an authorizable identity. Audit consumers
 * use the event class to distinguish role-catalogue mutations from
 * identity-level revocations.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionRevoked
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     */
    public function __construct(

        /** Role whose permission attachment was removed. */
        public Role $role,

        /** Permission that was detached from the role. */
        public Permission $permission,
    ) {}
}
