<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Identity;

use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Dispatched when an existing role assignment's expiry is mutated by a re-call
 * to `assignRole()`.
 *
 * `assignRole()` writes through `syncWithoutDetaching` and so silently
 * overwrites the prior pivot row's `expires_at`. Without a distinct signal a
 * consumer who re-assigns an existing forever grant with an expiry would
 * shorten it (or extend an expiring grant to forever) without an audit trail.
 * This event fires alongside `RoleAssigned` whenever the prior pivot's
 * `expires_at` differs from the supplied value, so audit consumers can render
 * the expiry mutation as its own row.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RoleExpiryChanged implements IdentityEvent
{
    /**
     * Create a new event instance.
     *
     * @param  object  $authorizable
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \DateTimeInterface|null  $previousExpiresAt
     * @param  \DateTimeInterface|null  $newExpiresAt
     */
    public function __construct(

        /** Authorizable identity whose role grant changed expiry. */
        public object $authorizable,

        /** Role whose pivot row had its `expires_at` mutated. */
        public Role $role,

        /** Pre-write `expires_at`; null indicates a forever grant. */
        public ?\DateTimeInterface $previousExpiresAt,

        /** Post-write `expires_at`; null indicates a forever grant. */
        public ?\DateTimeInterface $newExpiresAt,

    ) {}
}
