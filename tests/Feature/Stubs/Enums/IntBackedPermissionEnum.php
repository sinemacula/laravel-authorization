<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs\Enums;

use SineMacula\Laravel\Authorization\Contracts\PermissionEnum as PermissionEnumContract;

/**
 * Permission enum backed by integers, which the config validation refuses
 * because an integer is not a permission name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum IntBackedPermissionEnum: int implements PermissionEnumContract
{
    case POSTS_CREATE = 1;
}
