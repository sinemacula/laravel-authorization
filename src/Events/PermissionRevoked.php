<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * Dispatched when a direct permission is revoked from an authorizable
 * identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionRevoked
{
    /**
     * Create a new event instance.
     *
     * @param  object  $authorizable
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     */
    public function __construct(

        /** Authorizable identity that the direct permission was revoked from. */
        public object $authorizable,

        /** Permission that was revoked from the identity. */
        public Permission $permission,

    ) {}
}
