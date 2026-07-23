<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Policy;

use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * Dispatched after a new policy row is persisted.
 *
 * Part of the policy-catalogue lifecycle trio (`PolicyCreated`,
 * `PolicyUpdated`, `PolicyDeleted`) consumed by audit-log sinks.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Created
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     */
    public function __construct(

        /** Persisted policy row. */
        public Policy $policy,
    ) {}
}
