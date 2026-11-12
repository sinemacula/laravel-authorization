<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation\Enums;

/**
 * Why a decision event was reported (BL-72): what
 * `DecisionEvent::reportedBecause()` returns.
 *
 * A decision may have several of these reasons at once, a preview's denial of a
 * sensitive action say; the event names the most specific one the settings
 * report, in the order the cases are declared: a break-glass allow, a preview,
 * insufficient authentication, a denial, a sensitive action, then any allow.
 * Break-glass allows are reported whatever the settings once break-glass grants
 * arrive; until then no decision is reported as one.
 *
 * Part of the SemVer-stable event API; a case is never removed or renamed
 * without a major version bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum DecisionReport: string
{
    /** A break-glass grant allowed the check. */
    case BREAK_GLASS = 'break_glass';

    /** The decision was made through a preview, for its previewer. */
    case PREVIEW = 'preview';

    /** The check was denied because only its authentication requirement was unmet. */
    case INSUFFICIENT_AUTHENTICATION = 'insufficient_authentication';

    /** The check was denied. */
    case DENIAL = 'denial';

    /** The check was allowed, and its action is one of `events.decisions.sensitive_actions`. */
    case SENSITIVE_ACTION = 'sensitive_action';

    /** The check was allowed, and `events.decisions.allows` reports every allow. */
    case ALL_ALLOWS = 'all_allows';
}
