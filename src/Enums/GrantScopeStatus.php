<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Enums;

/**
 * Where an identity's grants lie against a tenant, as the grant scope query
 * answers it (AUTHZ-14.2).
 *
 * It carries the answer alone, never which grant, tenant or how many decided
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum GrantScopeStatus: string
{
    /** Every grant of the identity and its principals is rooted at the tenant or below it, or there is none. */
    case WITHIN = 'within';

    /** At least one grant is rooted outside the tenant: at an ancestor, a sibling, another tenant or the platform. */
    case OUTSIDE = 'outside';

    /** The answer cannot be given: the principals are not all known, the tree cannot be read, or a grant cannot. */
    case UNKNOWN = 'unknown';
}
