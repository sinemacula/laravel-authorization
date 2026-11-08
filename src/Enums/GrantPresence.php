<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Enums;

/**
 * Whether a principal holds a grant that applies in a tenant, as the principal
 * presence helper answers it (AUTHZ-13.8).
 *
 * It says nothing about membership of the tenant or permission to act there.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum GrantPresence: string
{
    /** A live grant of the principal, or of its identity when that identity's grants reach it, applies in the tenant (see `SubjectGrants::grantingIdentity()`). */
    case PRESENT = 'present';

    /** No live grant of the principal, or of its identity when that identity's grants reach it, applies in the tenant, and none could have been missed. */
    case ABSENT = 'absent';

    /** No grant was found, but one could not be ruled out: the tree or a grantee cannot be read. */
    case UNKNOWN = 'unknown';
}
