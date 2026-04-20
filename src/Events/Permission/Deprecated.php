<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Permission;

use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * Dispatched after a permission row is soft-retired by sync — the
 * `deprecated_at` column is stamped but the row, and any role pivots attached
 * to it, survive.
 *
 * Paired with `Reinstated` across the deprecation lifecycle.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Deprecated
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     */
    public function __construct(

        /** Permission row captured immediately after the soft retire. */
        public Permission $permission,

    ) {}
}
