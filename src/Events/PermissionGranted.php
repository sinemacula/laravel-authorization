<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * Dispatched when a permission is granted directly to an authorizable
 * identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionGranted
{
    /**
     * Create a new event instance.
     *
     * @param  object  $authorizable
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     */
    public function __construct(

        /** Authorizable identity that received the direct permission grant. */
        public object $authorizable,

        /** Permission that was granted directly to the identity. */
        public Permission $permission,

    ) {}
}
