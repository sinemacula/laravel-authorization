<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Identity;

use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Dispatched when a grant or sync rewrites the expiry of a role the identity
 * already holds.
 *
 * The grant service dispatches it alongside `RoleAssigned` when a grant changes
 * a live role's expiry, or when a grant or sync re-arms a role whose grant has
 * expired, so audit consumers can render the expiry change as its own row.
 * Without it, granting again a forever role with an expiry would shorten it (or
 * extend an expiring role to forever) without an audit trail.
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
