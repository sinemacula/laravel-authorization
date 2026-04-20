<?php

declare(strict_types = 1);

namespace Tests\Unit\Console\Support\Stubs;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;

/**
 * Fixture enum carrying a multi-guard attribute — exercises the per-guard
 * expansion path and validates that two tuples are emitted for one case.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum MultiGuardPermission: string implements PermissionEnum
{
    #[PermissionMeta(
        description: 'View applications',
        category: 'Applications',
        guards: ['web', 'api'],
    )]
    case VIEW_APPLICATIONS = 'applications:view';
}
