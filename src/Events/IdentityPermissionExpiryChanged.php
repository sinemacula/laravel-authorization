<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * Dispatched when an existing direct-permission grant's expiry is
 * mutated by a re-call to `givePermission()`.
 *
 * `givePermission()` writes through `syncWithoutDetaching` and so
 * silently overwrites the prior pivot row's `expires_at`. Without
 * a distinct signal a consumer who re-grants an existing forever
 * permission with an expiry would shorten it (or extend an
 * expiring grant to forever) without an audit trail. This event
 * fires alongside `IdentityPermissionGranted` whenever the prior
 * pivot's `expires_at` differs from the supplied value, so audit
 * consumers can render the expiry mutation as its own row.
 *
 * Part of the SemVer-stable event API; breaking changes require a
 * major version bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentityPermissionExpiryChanged
{
    /**
     * Create a new event instance.
     *
     * @param  object  $authorizable
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @param  \DateTimeInterface|null  $previousExpiresAt
     * @param  \DateTimeInterface|null  $newExpiresAt
     */
    public function __construct(

        /** Authorizable identity whose permission grant changed expiry. */
        public object $authorizable,

        /** Permission whose pivot row had its `expires_at` mutated. */
        public Permission $permission,

        /** Pre-write `expires_at`; null indicates a forever grant. */
        public ?\DateTimeInterface $previousExpiresAt,

        /** Post-write `expires_at`; null indicates a forever grant. */
        public ?\DateTimeInterface $newExpiresAt,

    ) {}
}
