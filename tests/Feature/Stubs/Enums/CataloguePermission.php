<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs\Enums;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum as PermissionEnumContract;

/**
 * Permission enum declaring a catalogue for the sync: one case with metadata
 * and no guards, one with metadata and two guards, and one without the
 * attribute.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum CataloguePermission: string implements PermissionEnumContract
{
    #[PermissionMeta(description: 'Create posts', category: 'Posts')]
    case POSTS_CREATE = 'posts:create';

    #[PermissionMeta(description: 'Publish posts', category: 'Posts', guards: ['web', 'api'])]
    case POSTS_PUBLISH = 'posts.publish';

    case POSTS_ARCHIVE = 'posts:archive';
}
