<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Enums;

/**
 * The question an access review asks (AUTHZ-11.6, N93): who holds a target,
 * what a subject holds, what expires within a window, what an actor last
 * granted, or what shows no observed use since an instant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ReviewKind: string
{
    /** Who holds a role, a permission or a policy in a scope. */
    case HOLDERS = 'holders';

    /** What a subject, or an identity and its principals, holds, and where. */
    case HOLDINGS = 'holdings';

    /** Which stored grants, attachments and role edges expire within a window. */
    case EXPIRING = 'expiring';

    /** Which stored grants an actor last granted or changed (N95). */
    case GRANTED_BY = 'granted_by';

    /** Which live stored grants show no observed use since an instant (N94). */
    case UNUSED = 'unused';
}
