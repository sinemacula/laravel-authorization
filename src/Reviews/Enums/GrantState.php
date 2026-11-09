<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Enums;

/**
 * Whether the stored row a review row names still counts at the review's
 * instant: a row with no expiry, or one whose expiry is after the instant, is
 * live, and one whose expiry is at the instant or before it has expired (see
 * `Database\LiveGrants`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum GrantState: string
{
    /** The row has no expiry, or expires after the review's instant. */
    case LIVE = 'live';

    /** The row expired at the review's instant or before it, and is kept until pruned. */
    case EXPIRED = 'expired';
}
