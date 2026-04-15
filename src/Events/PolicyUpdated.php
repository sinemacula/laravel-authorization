<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * Dispatched after a policy row is updated. Carries the pre-save
 * `changes` snapshot alongside the updated row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PolicyUpdated
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  array<string, mixed>  $changes
     */
    public function __construct(

        /** Updated policy row in its post-save state. */
        public Policy $policy,

        /** Attribute deltas captured at the moment of the save. */
        public array $changes,

    ) {}
}
