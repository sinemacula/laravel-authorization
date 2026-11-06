<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation\Enums;

/**
 * The stages of a decision, in the order they run (AUTHZ-7.1); the first that
 * decides ends it.
 *
 * Guardrails, boundaries and session policies take their places between the
 * denies and the allows as they arrive.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum DecisionStage: string
{
    /** The subject is unresolved or inactive. */
    case SUBJECT = 'subject';

    /** The resource could not be identified. */
    case RESOURCE = 'resource';

    /** The resource's tenant is outside the decision's scope. */
    case TENANT = 'tenant';

    /** An explicit deny, or a policy that cannot be evaluated, in any applicable policy. */
    case DENY = 'deny';

    /** An allow from a policy statement or a permission the subject holds. */
    case ALLOW = 'allow';

    /** Nothing allowed the check. */
    case IMPLICIT = 'implicit';
}
