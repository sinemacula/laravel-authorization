<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics\Enums;

/**
 * Where the package stands in an application that registered it: not yet
 * validated, validated and serving, or refusing every operation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum PackageStatus: string
{
    /** The package registered, and its configuration has not been validated yet, or its validation threw. */
    case PENDING = 'pending';

    /** The configuration was validated, and the package was set up: every operation runs. */
    case HEALTHY = 'healthy';

    /** The diagnostic boot found the configuration refused or could not check it completely: every operation refuses. */
    case REFUSING = 'refusing';
}
