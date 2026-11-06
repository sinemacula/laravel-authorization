<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation\Enums;

/**
 * The stages of a decision, in the order they run (AUTHZ-7.1); the first that
 * decides ends it.
 *
 * The subject, resource and tenant stages admit the check; then every explicit
 * deny is assessed, from every source; then the caps, guardrails, boundaries
 * and session caps, each of which can only deny; then the allows, from every
 * source; then the implicit deny. No allow is reached before every deny and
 * every cap has run.
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

    /** An explicit deny, or a policy that cannot be evaluated, in any applicable policy, guardrail or boundary. */
    case DENY = 'deny';

    /** A guardrail on the check's tenant, one of its ancestors or the platform does not allow the check. */
    case GUARDRAIL = 'guardrail';

    /** A permission boundary of the subject's principal or identity does not allow the check. */
    case BOUNDARY = 'boundary';

    /** A session cap, the credential's scopes, does not allow the check (BL-50; none apply yet). */
    case SESSION = 'session';

    /** An allow from a policy statement, a resource policy naming the subject, or a permission the subject holds. */
    case ALLOW = 'allow';

    /** Nothing allowed the check. */
    case IMPLICIT = 'implicit';
}
