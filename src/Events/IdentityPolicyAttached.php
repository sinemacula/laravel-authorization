<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * Dispatched when a policy is attached to an authorizable identity.
 *
 * Part of the SemVer-stable event API; breaking changes require a
 * major version bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentityPolicyAttached
{
    /**
     * Create a new event instance.
     *
     * @param  object  $authorizable
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     */
    public function __construct(

        /** Authorizable identity that the policy was attached to. */
        public object $authorizable,

        /** Policy row that was attached to the identity. */
        public Policy $policy,

    ) {}
}
