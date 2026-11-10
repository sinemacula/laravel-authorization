<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics\Enums;

/**
 * The outcome of the configuration report: every check passed, a setting was
 * refused, or the report itself could not be completed. A refusal wins over an
 * incomplete report.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ReportStatus: string
{
    /** Every check passed. */
    case PASSED = 'passed';

    /** At least one setting was refused. */
    case REFUSED = 'refused';

    /** No setting was refused, but a check or a part of the report could not be completed. */
    case INCOMPLETE = 'incomplete';

    /**
     * Return the exit code `authorization:check` ends with for the status: 0
     * passed, 1 refused, 3 incomplete (2 is a bad invocation).
     *
     * @return int
     */
    public function exitCode(): int
    {
        return match ($this) {
            self::PASSED     => 0,
            self::REFUSED    => 1,
            self::INCOMPLETE => 3,
        };
    }
}
