<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Identity;

use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * Dispatched when a grant or sync rewrites the expiry of a permission granted
 * directly to the identity.
 *
 * The grant service dispatches it alongside `PermissionGranted` when a grant
 * changes a live permission's expiry, or when a grant or sync re-arms a
 * permission whose grant has expired, so audit consumers can render the expiry
 * change as its own row. Without it, granting again a forever permission with
 * an expiry would shorten it (or extend an expiring grant to forever) without
 * an audit trail.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionExpiryChanged implements IdentityEvent
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
