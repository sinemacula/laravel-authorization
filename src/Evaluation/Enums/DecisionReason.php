<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation\Enums;

/**
 * Why a check was denied (AUTHZ-7.10); an allowed check carries none.
 *
 * Each code is 1 to 64 characters of lower-case letters, digits, `_`, `.`, `:`
 * and `-`, starting with a letter or digit, and any code added later keeps to
 * that grammar.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum DecisionReason: string
{
    /** An applicable policy statement denies the check. */
    case EXPLICIT_DENY = 'explicit_deny';

    /** No statement or permission names the action and the resource. */
    case NO_MATCH = 'no_match';

    /** A statement names the action and the resource, but its conditions do not hold. */
    case CONDITION_FAILED = 'condition_failed';

    /** An applicable policy cannot be evaluated, so the check is denied. */
    case INVALID_POLICY = 'invalid_policy';

    /** The subject, or its identity, is inactive. */
    case SUBJECT_INACTIVE = 'subject_inactive';

    /** There is no subject to decide about. */
    case SUBJECT_UNRESOLVED = 'subject_unresolved';

    /** The resource the check names cannot be identified. */
    case RESOURCE_UNRESOLVED = 'resource_unresolved';

    /** The resource's tenant is outside the decision's tenant and its subtree, and no platform-wide grant covers it. */
    case TENANT_SCOPE = 'tenant_scope';

    /** An allow statement names the check, and only its authentication requirement is unmet. */
    case INSUFFICIENT_AUTHENTICATION = 'insufficient_authentication';

    /** A guardrail on the check's tenant, one of its ancestors or the platform does not allow the check. */
    case GUARDRAIL = 'guardrail';

    /** A permission boundary of the subject's principal or identity does not allow the check. */
    case BOUNDARY = 'boundary';

    /** A session cap, the scopes of the subject's credential or a set of actions the caller passed, does not allow the check. */
    case SESSION_POLICY = 'session_policy';

    /** The administration operation reaches beyond the scope the actor administers. */
    case ADMINISTRATION_SCOPE = 'administration.scope';

    /** The administration operation edits a record from outside the tenant that owns it. */
    case ADMINISTRATION_OWNER = 'administration.owner';

    /** The rank of the actor or of the target of the administration operation cannot be compared. */
    case ADMINISTRATION_RANK_UNCOMPARABLE = 'administration.rank_uncomparable';

    /** The target of the administration operation is not junior to the actor. */
    case ADMINISTRATION_RANK = 'administration.rank';

    /** The administration operation benefits the actor itself, and nothing allows that. */
    case ADMINISTRATION_SELF = 'administration.self';

    /** The administration operation hands out what the actor neither holds nor may grant. */
    case ADMINISTRATION_NOT_GRANTABLE = 'administration.not_grantable';

    /** The administration operation may widen authority in a way the package cannot prove is permitted. */
    case ADMINISTRATION_UNPROVABLE = 'administration.unprovable';

    /** The administration operation is made while impersonating, and nothing allows that. */
    case ADMINISTRATION_IMPERSONATING = 'administration.impersonating';

    /** The administration operation was decided on records that changed before it was written, every time it was tried. */
    case ADMINISTRATION_CONFLICT = 'administration.conflict';

    /** A package mutation was asked for while a preview is evaluated, which no right allows. */
    case ADMINISTRATION_PREVIEWING = 'administration.previewing';

    /** @var array<string, string> The short description of each reason, for explanations, keyed by its value. */
    private const array LABELS = [
        'explicit_deny'                    => 'an applicable statement denies it',
        'no_match'                         => 'no statement or permission names it',
        'condition_failed'                 => 'a statement names it, but its conditions do not hold',
        'invalid_policy'                   => 'an applicable policy cannot be evaluated',
        'subject_inactive'                 => 'the subject or its identity is inactive',
        'subject_unresolved'               => 'there is no subject',
        'resource_unresolved'              => 'the resource cannot be identified',
        'tenant_scope'                     => 'the resource belongs to a tenant outside the scope',
        'insufficient_authentication'      => 'a statement allows it once further authentication is met',
        'guardrail'                        => 'a guardrail does not allow it',
        'boundary'                         => 'a permission boundary does not allow it',
        'session_policy'                   => 'a session cap does not allow it',
        'administration.scope'             => 'it reaches beyond the scope the actor administers',
        'administration.owner'             => 'it edits a record from outside the tenant that owns it',
        'administration.rank_uncomparable' => 'the ranks of the actor and the target cannot be compared',
        'administration.rank'              => 'the target is not junior to the actor',
        'administration.self'              => 'it benefits the actor itself',
        'administration.not_grantable'     => 'it hands out what the actor neither holds nor may grant',
        'administration.unprovable'        => 'it may widen authority in a way that cannot be proved permitted',
        'administration.impersonating'     => 'it is made while impersonating',
        'administration.conflict'          => 'what it was decided on changed before it was written',
        'administration.previewing'        => 'it is made while a preview is evaluated',
    ];

    /**
     * Return a short description of the reason, for explanations.
     *
     * @return string
     */
    public function label(): string
    {
        return self::LABELS[$this->value];
    }
}
