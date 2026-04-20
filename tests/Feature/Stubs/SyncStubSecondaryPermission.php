<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum as PermissionEnumContract;

/**
 * Secondary sync fixture with cases disjoint from `SyncStubPermission` so
 * multiple enum classes can be configured alongside each other without
 * colliding on the `(name, guard)` unique index.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum SyncStubSecondaryPermission: string implements PermissionEnumContract
{
    #[PermissionMeta(
        description: 'Assign roles',
        category: 'Security',
        guards: ['web'],
    )]
    case ROLES_ASSIGN = 'roles:assign';
}
