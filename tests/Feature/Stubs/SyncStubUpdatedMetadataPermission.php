<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum as PermissionEnumContract;

/**
 * Sync fixture sharing `POSTS_VIEW` with the base enum but carrying
 * drifted metadata — exercises the `update` bucket when a case's
 * description or category changes between sync passes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum SyncStubUpdatedMetadataPermission: string implements PermissionEnumContract
{
    #[PermissionMeta(
        description: 'View published posts',
        category: 'Publishing',
        guards: ['web', 'api'],
    )]
    case POSTS_VIEW = 'posts:view';

    case POSTS_DELETE = 'posts:delete';
}
