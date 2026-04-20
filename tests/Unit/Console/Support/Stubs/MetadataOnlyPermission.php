<?php

declare(strict_types = 1);

namespace Tests\Unit\Console\Support\Stubs;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;

/**
 * Fixture enum with populated description and category and no `guards` argument
 * — exercises the guard-agnostic expansion.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum MetadataOnlyPermission: string implements PermissionEnum
{
    #[PermissionMeta(
        description: 'Edit posts',
        category: 'Content',
    )]
    case EDIT_POSTS = 'posts:edit';
}
