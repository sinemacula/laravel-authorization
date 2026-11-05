<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Identity;

use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * Dispatched when an attachment or sync rewrites the expiry of a policy
 * attached to the identity.
 *
 * The grant service dispatches it alongside `PolicyAttached` when an attachment
 * changes a live policy's expiry, or when an attachment or sync re-arms a
 * policy whose attachment has expired, so audit consumers can render the expiry
 * change as its own row. Without it, attaching again a forever policy with an
 * expiry would shorten it (or extend an expiring attachment to forever) without
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
final readonly class PolicyExpiryChanged implements IdentityEvent
{
    /**
     * Create a new event instance.
     *
     * @param  object  $authorizable
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \DateTimeInterface|null  $previousExpiresAt
     * @param  \DateTimeInterface|null  $newExpiresAt
     */
    public function __construct(

        /** Authorizable identity whose policy attachment changed expiry. */
        public object $authorizable,

        /** Policy whose pivot row had its `expires_at` mutated. */
        public Policy $policy,

        /** Pre-write `expires_at`; null indicates a forever grant. */
        public ?\DateTimeInterface $previousExpiresAt,

        /** Post-write `expires_at`; null indicates a forever grant. */
        public ?\DateTimeInterface $newExpiresAt,
    ) {}
}
