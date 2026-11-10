<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Enums;

/**
 * What an access review knows of a grant route's use (N94, see
 * `Reviews\RowUsage`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum UsageStatus: string
{
    /** The route was observed in use within the window. */
    case USED = 'used';

    /** Tracking covered the whole window and the route was never observed in it. */
    case UNUSED = 'unused';

    /** Tracking was off, did not cover the whole window, or the route's source cannot report its use. */
    case UNKNOWN = 'unknown';
}
