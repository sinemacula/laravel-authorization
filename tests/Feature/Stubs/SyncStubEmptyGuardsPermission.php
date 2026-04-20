<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum as PermissionEnumContract;

/**
 * Sync fixture carrying an explicit empty `guards: []` attribute — exercises
 * the walker's `InvalidPermissionAttributeException` path from the sync command
 * integration surface.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum SyncStubEmptyGuardsPermission: string implements PermissionEnumContract
{
    #[PermissionMeta(guards: [])]
    case POSTS_BROKEN = 'posts:broken';
}
