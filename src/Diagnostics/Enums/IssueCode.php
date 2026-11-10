<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics\Enums;

/**
 * The stable code of an issue the configuration check lists: a refusal of a
 * setting, a check skipped because a setting it depends on was refused, or a
 * check that failed in a way the package did not foresee.
 *
 * The values are part of the report's versioned shape, so a case is never
 * renamed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum IssueCode: string
{
    /** A block sets a key the package does not define. */
    case UNKNOWN_KEY = 'unknown_key';

    /** The value is not of the type the setting expects. */
    case INVALID_TYPE = 'invalid_type';

    /** A number is outside the range the setting allows. */
    case OUT_OF_RANGE = 'out_of_range';

    /** The value names a class that does not exist. */
    case UNKNOWN_CLASS = 'unknown_class';

    /** The value names a class that does not implement or extend what the setting needs. */
    case NOT_IMPLEMENTED = 'not_implemented';

    /** The value names an entry of another configuration map that does not exist. */
    case UNKNOWN_NAME = 'unknown_name';

    /** The value repeats a name another entry already holds. */
    case DUPLICATE = 'duplicate';

    /** The setting is null where a value is required. */
    case REQUIRED = 'required';

    /** The value is of the right type but its shape or content is refused. */
    case INVALID_VALUE = 'invalid_value';

    /** A permission the configuration declares is refused. */
    case INVALID_CATALOGUE = 'invalid_catalogue';

    /** The check was not run, because a setting it depends on was refused. */
    case SKIPPED = 'skipped';

    /** The check failed in a way the package did not foresee, so the report is incomplete. */
    case INTERNAL = 'internal';

    /**
     * Determine whether the issue refuses the configuration: every code but
     * `skipped` and `internal`.
     *
     * @return bool
     */
    public function isRefusal(): bool
    {
        return $this !== self::SKIPPED && $this !== self::INTERNAL;
    }
}
