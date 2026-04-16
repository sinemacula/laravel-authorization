<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * Dispatched after a policy row is deleted. Carries the final
 * snapshot before the source row disappears.
 *
 * Part of the SemVer-stable event API; breaking changes require a
 * major version bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PolicyDeleted
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     */
    public function __construct(

        /** Policy row captured immediately after deletion. */
        public Policy $policy,

    ) {}
}
