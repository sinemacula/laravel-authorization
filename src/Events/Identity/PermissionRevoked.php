<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Identity;

use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * Dispatched when a direct permission is revoked from an authorizable identity.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionRevoked implements IdentityEvent
{
    /**
     * Create a new event instance.
     *
     * @param  object  $authorizable
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     */
    public function __construct(

        /** Authorizable identity from which the permission was revoked. */
        public object $authorizable,

        /** Permission that was revoked from the identity. */
        public Permission $permission,

    ) {}
}
