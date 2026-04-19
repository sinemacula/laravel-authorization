<?php

declare(strict_types = 1);

namespace Tests\Unit\Console\Support\Stubs;

use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;

/**
 * Fixture enum with cases that carry no `#[Permission]` attribute.
 * Exercises the default-metadata walk path.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum NoAttributePermission: string implements PermissionEnum
{
    case DELETE_APPLICATIONS = 'applications:delete';
}
