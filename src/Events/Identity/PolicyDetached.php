<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Identity;

use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * Dispatched when a policy is detached from an authorizable identity.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PolicyDetached implements IdentityEvent
{
    /**
     * Create a new event instance.
     *
     * @param  object  $authorizable
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     */
    public function __construct(

        /** Authorizable identity that the policy was detached from. */
        public object $authorizable,

        /** Policy row that was detached from the identity. */
        public Policy $policy,

    ) {}
}
