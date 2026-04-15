<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * Dispatched after a permission row is updated. Carries the
 * pre-save `changes` snapshot alongside the updated row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionUpdated
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @param  array<string, mixed>  $changes
     */
    public function __construct(

        /** Updated permission row in its post-save state. */
        public Permission $permission,

        /** Attribute deltas captured at the moment of the save. */
        public array $changes,

    ) {}
}
