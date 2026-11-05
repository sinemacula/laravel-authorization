<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs\Enums;

use SineMacula\Laravel\Authorization\Contracts\PermissionEnum as PermissionEnumContract;

/**
 * Permission enum declaring a valid permission, then one whose name breaks the
 * package's name rules.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum InvalidNamePermission: string implements PermissionEnumContract
{
    case VALID  = 'reports:view';
    case SPACED = 'reports edit';
}
