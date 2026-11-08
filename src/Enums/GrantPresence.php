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
    /** The principal, or its identity, holds a live grant that applies in the tenant. */
    case PRESENT = 'present';

    /** Neither the principal nor its identity holds a live grant that applies in the tenant. */
    case ABSENT = 'absent';

    /** No grant was found, but one could not be ruled out: the tree or a grantee cannot be read. */
    case UNKNOWN = 'unknown';
}
