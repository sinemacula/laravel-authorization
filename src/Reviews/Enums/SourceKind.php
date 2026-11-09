<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Enums;

/**
 * The kind of source a row of an access review comes from (N93): a stored grant
 * held directly, a route through a role, or a stored role edge or role
 * attachment.
 *
 * The cases are declared in the order a review lists its rows, kind by kind
 * (see `Reviews\Support\ReviewOrder`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum SourceKind: string
{
    /** A role granted to the grantee. */
    case ROLE_GRANT = 'role_grant';

    /** A role held through a role below it that is granted to the grantee. */
    case ROLE_INHERITED = 'role_inherited';

    /** A permission granted directly to the grantee. */
    case PERMISSION_GRANT = 'permission_grant';

    /** A permission held through a role granted to the grantee, the role itself or a role above it carrying it. */
    case ROLE_PERMISSION = 'role_permission';

    /** A policy attached directly to the grantee, a policy that only denies included. */
    case POLICY_ATTACHMENT = 'policy_attachment';

    /** A policy held through a role granted to the grantee, attached to the role itself or a role above it. */
    case ROLE_POLICY = 'role_policy';

    /** A stored edge carrying a permission on a role. */
    case ROLE_PERMISSION_EDGE = 'role_permission_edge';

    /** A stored attachment of a policy to a role. */
    case ROLE_POLICY_ATTACHMENT = 'role_policy_attachment';

    /**
     * Return the position of the kind in the order a review lists its rows.
     *
     * @return int
     */
    public function position(): int
    {
        return (int) \array_search($this, self::cases(), true);
    }
}
