<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum as PermissionEnumContract;

/**
 * Sync fixture missing the `POSTS_DELETE` case — exercises the
 * `retire` bucket when a case is removed between sync passes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum SyncStubReducedPermission: string implements PermissionEnumContract
{
    #[PermissionMeta(
        description: 'View posts',
        category: 'Content',
        guards: ['web', 'api'],
    )]
    case POSTS_VIEW = 'posts:view';
}
