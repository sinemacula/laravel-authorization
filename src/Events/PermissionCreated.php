<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * Dispatched after a new permission row is persisted.
 *
 * Part of the permission-catalogue lifecycle trio
 * (`PermissionCreated`, `PermissionUpdated`, `PermissionDeleted`)
 * consumed by audit-log sinks.
 *
 * Part of the SemVer-stable event API; breaking changes require a
 * major version bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionCreated
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     */
    public function __construct(

        /** Persisted permission row. */
        public Permission $permission,

    ) {}
}
