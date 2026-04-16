<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Dispatched after a role row is updated.
 *
 * Carries the full before/after diff so audit consumers can render
 * the change set without a second round-trip. The `before` map
 * holds the pre-save values for every dirty attribute (sourced via
 * `getOriginal()` at the moment the update fired); the `after`
 * map holds the post-save values (sourced via `getChanges()`).
 * Both maps share the same key set.
 *
 * Part of the SemVer-stable event API; breaking changes require a
 * major version bump.
 *
 * @api
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
     * @param  array{before: array<string, mixed>, after: array<string, mixed>}  $changes
     */
    public function __construct(

        /** Updated role row in its post-save state. */
        public Role $role,

        /**
         * Before/after attribute diff captured across the update.
         *
         * @var array{before: array<string, mixed>, after: array<string, mixed>}
         */
        public array $changes,

    ) {}
}
