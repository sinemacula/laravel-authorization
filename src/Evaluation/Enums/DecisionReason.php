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

    /** The administration operation may widen authority in a way the package cannot yet prove is permitted. */
    case ADMINISTRATION_UNPROVABLE = 'administration.unprovable';

    /** The administration operation is made while impersonating, and nothing allows that. */
    case ADMINISTRATION_IMPERSONATING = 'administration.impersonating';

    /**
     * Return a short description of the reason, for explanations.
     *
     * @return string
     */
    public function label(): string
    {
        return match ($this) {
            self::EXPLICIT_DENY                    => 'an applicable statement denies it',
            self::NO_MATCH                         => 'no statement or permission names it',
            self::CONDITION_FAILED                 => 'a statement names it, but its conditions do not hold',
            self::INVALID_POLICY                   => 'an applicable policy cannot be evaluated',
            self::SUBJECT_INACTIVE                 => 'the subject or its identity is inactive',
            self::SUBJECT_UNRESOLVED               => 'there is no subject',
            self::RESOURCE_UNRESOLVED              => 'the resource cannot be identified',
            self::TENANT_SCOPE                     => 'the resource belongs to a tenant outside the scope',
            self::INSUFFICIENT_AUTHENTICATION      => 'a statement allows it once further authentication is met',
            self::GUARDRAIL                        => 'a guardrail does not allow it',
            self::BOUNDARY                         => 'a permission boundary does not allow it',
            self::SESSION_POLICY                   => 'a session cap does not allow it',
            self::ADMINISTRATION_SCOPE             => 'it reaches beyond the scope the actor administers',
            self::ADMINISTRATION_OWNER             => 'it edits a record from outside the tenant that owns it',
            self::ADMINISTRATION_RANK_UNCOMPARABLE => 'the ranks of the actor and the target cannot be compared',
            self::ADMINISTRATION_RANK              => 'the target is not junior to the actor',
            self::ADMINISTRATION_SELF              => 'it benefits the actor itself',
            self::ADMINISTRATION_NOT_GRANTABLE     => 'it hands out what the actor neither holds nor may grant',
            self::ADMINISTRATION_UNPROVABLE        => 'it may widen authority in a way that cannot yet be proved permitted',
            self::ADMINISTRATION_IMPERSONATING     => 'it is made while impersonating',
        };
    }
}
