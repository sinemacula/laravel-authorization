<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum as PermissionEnumContract;

/**
 * Sync fixture carrying the base cases plus a single additional
 * case — exercises the `add` bucket when the enum catalogue grows
 * between sync passes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum SyncStubExtendedPermission: string implements PermissionEnumContract
{
    #[PermissionMeta(
        description: 'View posts',
        category: 'Content',
        guards: ['web', 'api'],
    )]
    case POSTS_VIEW = 'posts:view';

    case POSTS_DELETE = 'posts:delete';

    #[PermissionMeta(
        description: 'Create posts',
        category: 'Content',
        guards: ['web'],
    )]
    case POSTS_CREATE = 'posts:create';
}
