<?php

declare(strict_types = 1);

namespace Tests\Unit\Console\Support\Stubs;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;

/**
 * Secondary fixture enum used to assert that the walker aggregates cases across
 * multiple enum classes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum SecondaryPermission: string implements PermissionEnum
{
    #[PermissionMeta(
        description: 'Assign roles',
        category: 'Security',
    )]
    case ASSIGN_ROLES = 'roles:assign';
}
