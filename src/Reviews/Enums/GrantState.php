<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Enums;

/**
 * The state of the stored rows a review row rests on, at the review's instant:
 *
 * - `live`: the row a route starts from has no expiry, or one after the instant
 *   (see `Database\LiveGrants`);
 * - `expired`: its expiry is at the instant or before it;
 * - `malformed`: the row, or one the route rests on, names half a tenant, a
 *   tenant type without a key or a key without a type, which the package never
 *   writes. Its origin scope shows the columns as they are stored. A check
 *   reads a key without a type at the platform, by its missing type alone, and
 *   a type without a key nowhere, and a review lists such a row exactly where a
 *   check reads it, and a type without a key in a review of everywhere too, of
 *   holders, holdings, expiries or an actor's grants, never in a review rooted
 *   within a tenant (N96). A malformed row is marked so whether or not it has
 *   expired.
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

    /** The row, or one the route rests on, names half a tenant: a type without a key, or a key without a type. */
    case MALFORMED = 'malformed';
}
