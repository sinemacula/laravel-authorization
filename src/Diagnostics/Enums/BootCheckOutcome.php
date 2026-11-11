<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics\Enums;

/**
 * What became of one of the checks the diagnostic boot runs by building what
 * the configuration names.
 *
 * The values are part of what the configuration report may show, so a case is
 * never renamed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum BootCheckOutcome: string
{
    /** The check ran and passed. */
    case PASSED = 'passed';

    /** The check ran and threw. */
    case FAILED = 'failed';

    /** The check did not run: the structural check found an issue, or the setting names nothing to build. */
    case NOT_RUN = 'not_run';
}
