<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Enums;

/**
 * The identifier each change event's `operation()` returns.
 *
 * Part of the SemVer-stable event API; a case is never removed or renamed
 * without a major version bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum MutationOperation: string
{
    case GRANTEE_ROLE_ASSIGNED             = 'grantee.role.assigned';
    case GRANTEE_ROLE_REVOKED              = 'grantee.role.revoked';
    case GRANTEE_ROLE_EXPIRY_CHANGED       = 'grantee.role.expiry_changed';
    case GRANTEE_ROLE_EXPIRED              = 'grantee.role.expired';
    case GRANTEE_PERMISSION_GRANTED        = 'grantee.permission.granted';
    case GRANTEE_PERMISSION_REVOKED        = 'grantee.permission.revoked';
    case GRANTEE_PERMISSION_EXPIRY_CHANGED = 'grantee.permission.expiry_changed';
    case GRANTEE_PERMISSION_EXPIRED        = 'grantee.permission.expired';
    case GRANTEE_POLICY_ATTACHED           = 'grantee.policy.attached';
    case GRANTEE_POLICY_DETACHED           = 'grantee.policy.detached';
    case GRANTEE_POLICY_EXPIRY_CHANGED     = 'grantee.policy.expiry_changed';
    case GRANTEE_POLICY_EXPIRED            = 'grantee.policy.expired';
    case GRANTEE_BOUNDARY_SET              = 'grantee.boundary.set';
    case GRANTEE_BOUNDARY_REMOVED          = 'grantee.boundary.removed';
    case GRANTEE_BREAK_GLASS_ACTIVATED     = 'grantee.break_glass.activated';
    case GRANTEE_BREAK_GLASS_SURRENDERED   = 'grantee.break_glass.surrendered';
    case GRANTEE_BREAK_GLASS_REVOKED       = 'grantee.break_glass.revoked';
    case GRANTEE_BREAK_GLASS_EXPIRED       = 'grantee.break_glass.expired';
    case ROLE_CREATED                      = 'role.created';
    case ROLE_UPDATED                      = 'role.updated';
    case ROLE_DELETED                      = 'role.deleted';
    case ROLE_PERMISSION_GRANTED           = 'role.permission.granted';
    case ROLE_PERMISSION_REVOKED           = 'role.permission.revoked';
    case ROLE_PERMISSION_EXPIRY_CHANGED    = 'role.permission.expiry_changed';
    case ROLE_PERMISSION_EXPIRED           = 'role.permission.expired';
    case PERMISSION_CREATED                = 'permission.created';
    case PERMISSION_UPDATED                = 'permission.updated';
    case PERMISSION_DELETED                = 'permission.deleted';
    case POLICY_CREATED                    = 'policy.created';
    case POLICY_UPDATED                    = 'policy.updated';
    case POLICY_DELETED                    = 'policy.deleted';
    case RESOURCE_POLICY_ATTACHED          = 'resource.policy.attached';
    case RESOURCE_POLICY_DETACHED          = 'resource.policy.detached';
    case GUARDRAIL_SET                     = 'guardrail.set';
    case GUARDRAIL_REMOVED                 = 'guardrail.removed';
    case ROLE_EXCLUSION_DECLARED           = 'role.exclusion.declared';
    case ROLE_EXCLUSION_REMOVED            = 'role.exclusion.removed';
}
