<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum as PermissionEnumContract;

/**
 * Base sync-command fixture enum — an annotated case expanding into two guards
 * and a bare case with no attribute, covering the guard-specific and
 * guard-agnostic expansion paths from a single fresh-install sync.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum SyncStubPermission: string implements PermissionEnumContract
{
    #[PermissionMeta(
        description: 'View posts',
        category: 'Content',
        guards: ['web', 'api'],
    )]
    case POSTS_VIEW = 'posts:view';

    case POSTS_DELETE = 'posts:delete';
}
