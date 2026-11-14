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
    case IDENTITY_ROLE_ASSIGNED             = 'identity.role.assigned';
    case IDENTITY_ROLE_REVOKED              = 'identity.role.revoked';
    case IDENTITY_ROLE_EXPIRY_CHANGED       = 'identity.role.expiry_changed';
    case IDENTITY_ROLE_EXPIRED              = 'identity.role.expired';
    case IDENTITY_PERMISSION_GRANTED        = 'identity.permission.granted';
    case IDENTITY_PERMISSION_REVOKED        = 'identity.permission.revoked';
    case IDENTITY_PERMISSION_EXPIRY_CHANGED = 'identity.permission.expiry_changed';
    case IDENTITY_PERMISSION_EXPIRED        = 'identity.permission.expired';
    case IDENTITY_POLICY_ATTACHED           = 'identity.policy.attached';
    case IDENTITY_POLICY_DETACHED           = 'identity.policy.detached';
    case IDENTITY_POLICY_EXPIRY_CHANGED     = 'identity.policy.expiry_changed';
    case IDENTITY_POLICY_EXPIRED            = 'identity.policy.expired';
    case IDENTITY_BOUNDARY_SET              = 'identity.boundary.set';
    case IDENTITY_BOUNDARY_REMOVED          = 'identity.boundary.removed';
    case IDENTITY_BREAK_GLASS_ACTIVATED     = 'identity.break_glass.activated';
    case IDENTITY_BREAK_GLASS_SURRENDERED   = 'identity.break_glass.surrendered';
    case IDENTITY_BREAK_GLASS_REVOKED       = 'identity.break_glass.revoked';
    case IDENTITY_BREAK_GLASS_EXPIRED       = 'identity.break_glass.expired';
    case ROLE_CREATED                       = 'role.created';
    case ROLE_UPDATED                       = 'role.updated';
    case ROLE_DELETED                       = 'role.deleted';
    case ROLE_PERMISSION_GRANTED            = 'role.permission.granted';
    case ROLE_PERMISSION_REVOKED            = 'role.permission.revoked';
    case ROLE_PERMISSION_EXPIRY_CHANGED     = 'role.permission.expiry_changed';
    case ROLE_PERMISSION_EXPIRED            = 'role.permission.expired';
    case PERMISSION_CREATED                 = 'permission.created';
    case PERMISSION_UPDATED                 = 'permission.updated';
    case PERMISSION_DELETED                 = 'permission.deleted';
    case POLICY_CREATED                     = 'policy.created';
    case POLICY_UPDATED                     = 'policy.updated';
    case POLICY_DELETED                     = 'policy.deleted';
    case RESOURCE_POLICY_ATTACHED           = 'resource.policy.attached';
    case RESOURCE_POLICY_DETACHED           = 'resource.policy.detached';
    case GUARDRAIL_SET                      = 'guardrail.set';
    case GUARDRAIL_REMOVED                  = 'guardrail.removed';
    case ROLE_EXCLUSION_DECLARED            = 'role.exclusion.declared';
    case ROLE_EXCLUSION_REMOVED             = 'role.exclusion.removed';
}
