<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Permission;

use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * Dispatched after a previously-deprecated permission row has its
 * `deprecated_at` column cleared by sync — the row is live again and any
 * surviving role pivots immediately participate in authorization decisions.
 *
 * Paired with `Deprecated` across the deprecation lifecycle.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Reinstated
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     */
    public function __construct(

        /** Permission row captured immediately after the reinstate. */
        public Permission $permission,

    ) {}
}
