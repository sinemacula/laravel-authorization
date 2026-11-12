<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation\Enums;

/**
 * How a grant that allowed a check reached its subject, as an explanation
 * records it (AUTHZ-11.5): a permission granted to the grantee, or through one
 * of its roles; a policy attached to the grantee, or to one of its roles; a
 * permission or policy of a role held through a break-glass activation; a
 * policy attached to the resource; or a source that cannot say.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum GrantSource: string
{
    /** A permission granted to the grantee itself. */
    case PERMISSION = 'permission';

    /** A permission a role carries, held by the grantee or reached through the role hierarchy. */
    case ROLE_PERMISSION = 'role_permission';

    /** A policy attached to the grantee itself. */
    case POLICY = 'policy';

    /** A policy attached to a role, held by the grantee or reached through the role hierarchy. */
    case ROLE_POLICY = 'role_policy';

    /** A permission a role carries, held by the grantee through a break-glass activation or reached through the role hierarchy from one. */
    case BREAK_GLASS_PERMISSION = 'break_glass_permission';

    /** A policy attached to a role, held by the grantee through a break-glass activation or reached through the role hierarchy from one. */
    case BREAK_GLASS_POLICY = 'break_glass_policy';

    /** A policy attached to the resource or its type, whose allow names the subject. */
    case RESOURCE_POLICY = 'resource_policy';

    /** A source that cannot say how the grant reached the subject, such as a custom resolver or a policy store. */
    case UNAVAILABLE = 'unavailable';
}
