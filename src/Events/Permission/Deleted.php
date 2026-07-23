<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Permission;

use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * Dispatched after a permission row is deleted. Carries the final snapshot
 * before the source row disappears.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Deleted
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     */
    public function __construct(

        /** Permission row captured immediately after deletion. */
        public Permission $permission,
    ) {}
}
