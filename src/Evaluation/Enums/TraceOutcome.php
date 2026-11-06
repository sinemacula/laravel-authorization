<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation\Enums;

/**
 * What one step of a decision found: a statement's assessment, whether the
 * subject holds the permission named by the action, that a guardrail or a
 * permission boundary does not allow the check, or that a cap stage found
 * nothing to cap the check by.
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

    /** The guardrail or permission boundary does not allow the check: no allow statement of its own allows it, or it has none. */
    case REFUSED = 'refused';

    /** No guardrail, boundary or session cap applies at the stage, so it caps nothing. */
    case UNCAPPED = 'uncapped';
}
