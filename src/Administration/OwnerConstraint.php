<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Only the owner edits (D20): a delegated change to a record is made from the
 * tenant that owns it, the platform's records from the platform.
 *
 * A tenant sees its own records, its ancestors' and the platform's, counts them
 * in its checks and may grant them where the grant scopes allow, but seeing a
 * record from a descendant is no authority to edit it: an operator who
 * administers the owner enters the owner's context first. The record is
 * whatever the change edits: a grant row, in the tenant it is held in, or, from
 * a later part of BL-65, a definition, in the tenant that owns it, a role's
 * membership or a policy. Granting an ancestor's role or permission to a local
 * grantee edits the local grant row, not the record granted, so it is weighed
 * against the grant row's tenant alone.
 *
 * The context is the tenant the check is made from, the request's, before the
 * operation's own tenant is put in place (see `FurtherChecks`), compared byte
 * for byte, so a change from the platform edits the platform's records alone,
 * and one from a tenant that tenant's alone. A change it refuses is refused as
 * `administration.owner`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class OwnerConstraint
{
    /**
     * Determine whether a change made from the context edits a record the
     * context owns: the owner and the context are the same tenant, or both the
     * platform.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $owner
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $context
     * @return bool
     */
    public static function isOwner(?Reference $owner, ?Reference $context): bool
    {
        if ($owner === null || $context === null) {
            return $owner === $context;
        }

        return $owner->type === $context->type && $owner->id === $context->id;
    }
}
