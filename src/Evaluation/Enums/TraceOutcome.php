<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation\Enums;

/**
 * What one step of a decision found: a statement's assessment, whether the
 * subject holds the permission named by the action, that a guardrail, a
 * permission boundary or a session cap does not allow the check, that a session
 * cap covers it, that a cap stage found nothing to cap the check by, or that
 * the check is exempt from a cap stage.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum TraceOutcome: string
{
    /** The statement does not name the action or the resource. */
    case NOT_APPLICABLE = 'not_applicable';

    /** The allow statement names the action but not the subject: a resource policy's principals do not name it, or a policy attached any other way carries principals. */
    case PRINCIPAL_MISMATCH = 'principal_mismatch';

    /** The statement names the action and the resource, and its conditions hold. */
    case MATCHED = 'matched';

    /** The statement names the action and the resource, but its conditions do not hold. */
    case CONDITION_FAILED = 'condition_failed';

    /** The statement names the action, but a value it needs is missing or cannot be resolved. */
    case UNDECIDABLE = 'undecidable';

    /** The statement cannot be evaluated. */
    case INVALID = 'invalid';

    /** The subject holds the permission the action names. */
    case HELD = 'held';

    /** The subject does not hold the permission the action names. */
    case NOT_HELD = 'not_held';

    /** The guardrail, permission boundary or session cap does not allow the check: no allow statement of its own allows it, or it has none, or no pattern of the session cap covers the action. */
    case REFUSED = 'refused';

    /** A pattern of the session cap covers the action. */
    case COVERED = 'covered';

    /** No guardrail, boundary or session cap applies at the stage, so it caps nothing. */
    case UNCAPPED = 'uncapped';

    /** The check is exempt from the stage, so none of its caps is read or weighed: the guardrail stage for `authorization:guardrails:manage`. */
    case EXEMPT = 'exempt';
}
