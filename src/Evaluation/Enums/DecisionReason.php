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

    /**
     * Return a short description of the reason, for explanations.
     *
     * @return string
     */
    public function label(): string
    {
        return match ($this) {
            self::EXPLICIT_DENY       => 'an applicable statement denies it',
            self::NO_MATCH            => 'no statement or permission names it',
            self::CONDITION_FAILED    => 'a statement names it, but its conditions do not hold',
            self::INVALID_POLICY      => 'an applicable policy cannot be evaluated',
            self::SUBJECT_INACTIVE    => 'the subject or its identity is inactive',
            self::SUBJECT_UNRESOLVED  => 'there is no subject',
            self::RESOURCE_UNRESOLVED => 'the resource cannot be identified',
            self::TENANT_SCOPE        => 'the resource belongs to a tenant outside the scope',
        };
    }
}
