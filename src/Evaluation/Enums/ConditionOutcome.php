<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation\Enums;

/**
 * What one condition test of a statement found, as an explanation records it
 * (AUTHZ-11.5): that it held or failed, or why it could not be decided, never
 * the value it read or the operand it compared it with (AUTHZ-8.8).
 *
 * A key the context lacks is `missing` when the test cannot be decided without
 * it. A test that passes on a missing key, under `_if_exists` or as `null:
 * true`, `held`, and one that `null: false` refuses `failed`; the test then
 * says the key was missing. A key present with a null value that the test does
 * not accept is `null`, since every operator but `null` tests the null itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ConditionOutcome: string
{
    /** The test holds. */
    case HELD = 'held';

    /** The test definitely does not hold. */
    case FAILED = 'failed';

    /** The key is missing from the context, so the test cannot be decided. */
    case MISSING = 'missing';

    /** The key holds a null the test does not accept. */
    case NULL = 'null';

    /** The key holds a value of a type the operator cannot compare, so the test cannot be decided. */
    case WRONG_TYPE = 'wrong_type';

    /** A `${…}` reference of the operand cannot be resolved, so the test cannot be decided. */
    case UNRESOLVED = 'unresolved';

    /** The test cannot be decided for another reason: a substituted operand of the wrong type, or an authentication requirement that cannot be checked. */
    case UNDECIDABLE = 'undecidable';

    /** The test is malformed, so the statement cannot be evaluated. */
    case INVALID = 'invalid';

    /**
     * Determine whether the test holds.
     *
     * @return bool
     */
    public function holds(): bool
    {
        return $this === self::HELD;
    }
}
