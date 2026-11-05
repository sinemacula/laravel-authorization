<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs\Enums;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum as PermissionEnumContract;

/**
 * Permission enum whose cases each list a guard that is not a non-empty string,
 * which is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum InvalidGuardsPermission: string implements PermissionEnumContract
{
    #[PermissionMeta(guards: ['web', null])] // @phpstan-ignore argument.type
    case NULL_GUARD = 'reports:null';

    #[PermissionMeta(guards: [1])] // @phpstan-ignore argument.type
    case INTEGER_GUARD = 'reports:integer';

    #[PermissionMeta(guards: ['web', ''])]
    case EMPTY_GUARD = 'reports:empty';
}
