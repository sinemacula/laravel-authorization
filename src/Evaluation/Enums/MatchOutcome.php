<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation\Enums;

/**
 * Outcome of testing a statement, or one of its parts, against a check.
 *
 * Two outcomes beyond a plain yes or no keep the evaluator fail-closed:
 *
 * - `UNDECIDABLE`: the test could not be decided from the check, because a
 *   context key is missing, a `${…}` reference cannot be resolved or a context
 *   value has the wrong type. A deny statement applies; an allow does not.
 * - `INVALID`: the statement itself is malformed (an unknown operator, an
 *   operand of the wrong type). The whole check denies.
 *
 * When parts are combined (every condition of a statement, every operator of a
 * condition), the strongest outcome wins in the order invalid, does not match,
 * undecidable, matches: one part that definitely fails decides the conjunction
 * even if another part could not be decided.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum MatchOutcome: string
{
    /** Every part of the test holds. */
    case MATCHES = 'matches';

    /** At least one part definitely does not hold. */
    case DOES_NOT_MATCH = 'does_not_match';

    /** No part fails, but at least one could not be decided. */
    case UNDECIDABLE = 'undecidable';

    /** The statement is malformed; the check denies. */
    case INVALID = 'invalid';

    /**
     * Return the precedence of the outcome when parts are combined; the higher
     * value wins.
     *
     * @return int
     */
    public function precedence(): int
    {
        return match ($this) {
            self::MATCHES        => 0,
            self::UNDECIDABLE    => 1,
            self::DOES_NOT_MATCH => 2,
            self::INVALID        => 3,
        };
    }
}
