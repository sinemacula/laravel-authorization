<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Only the owner edits (D20): a delegated change to a definition is made from
 * the tenant that owns it, the platform's definitions from the platform.
 *
 * A tenant sees its own records, its ancestors' and the platform's, counts them
 * in its checks and may grant them where the grant scopes allow, but seeing a
 * record from a descendant is no authority to edit it: an operator who
 * administers the owner enters the owner's context first. The record is a
 * definition, a role, permission or policy, with its membership and its
 * attachments: the administration stage applies the rule to every change to a
 * definition, to a role's permissions, policies or parent (see
 * `DefinitionConstraints`). A grant row is never such a record (N79): who may
 * change one is the scope the actor administers (see `OperationConstraints`),
 * so this rule never weighs a grant.
 *
 * The context is the tenant the check is made from (see `FurtherChecks`),
 * compared byte for byte, so a change from the platform edits the platform's
 * records alone, and one from a tenant that tenant's alone. A change it refuses
 * is refused as `administration.owner`.
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
