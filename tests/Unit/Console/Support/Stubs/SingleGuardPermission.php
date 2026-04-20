<?php

declare(strict_types = 1);

namespace Tests\Unit\Console\Support\Stubs;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;

/**
 * Fixture enum carrying a single-guard attribute — exercises single-element
 * guard expansion.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum SingleGuardPermission: string implements PermissionEnum
{
    #[PermissionMeta(
        description: 'Publish posts',
        category: 'Content',
        guards: ['web'],
    )]
    case PUBLISH_POSTS = 'posts:publish';
}
