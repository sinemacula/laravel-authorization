<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Enums;

/**
 * What a grant through the management services changed.
 *
 * A grant of what the grantee already holds, with the same expiry, changes
 * nothing and is reported as unchanged; the services dispatch no event for it.
 * Re-granting a grant that has expired re-arms it with the new expiry, and
 * changing the expiry of a live grant is reported as a change of its own, as is
 * changing whether a grant in a tenant reaches the tenants below it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum GrantOutcome: string
{
    /** The grantee did not hold the grant, and now does. */
    case GRANTED = 'granted';

    /** The grant had expired, and now holds again until the new expiry. */
    case REARMED = 'rearmed';

    /** The grant was live, and now carries a different expiry. */
    case EXPIRY_CHANGED = 'expiry_changed';

    /** The grant was held with the same expiry, and now reaches the tenants below its tenant, or no longer does. */
    case REACH_CHANGED = 'reach_changed';

    /** The grantee already held the grant with the same expiry. */
    case UNCHANGED = 'unchanged';

    /**
     * Determine whether the grant wrote anything.
     *
     * @return bool
     */
    public function isChange(): bool
    {
        return $this !== self::UNCHANGED;
    }
}
