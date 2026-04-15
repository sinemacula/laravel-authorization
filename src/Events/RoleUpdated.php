<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Dispatched after a role row is updated.
 *
 * Carries both the pre-save `changes` snapshot and the updated
 * row so audit consumers can render a before/after diff without a
 * second round-trip.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RoleUpdated
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  array<string, mixed>  $changes
     */
    public function __construct(

        /** Updated role row in its post-save state. */
        public Role $role,

        /** Attribute deltas captured at the moment of the save. */
        public array $changes,

    ) {}
}
