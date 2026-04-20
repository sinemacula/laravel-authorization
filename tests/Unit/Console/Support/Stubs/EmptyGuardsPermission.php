<?php

declare(strict_types = 1);

namespace Tests\Unit\Console\Support\Stubs;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;

/**
 * Fixture enum carrying an explicit empty `guards: []` array — the walker must
 * reject this configuration with a typed exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum EmptyGuardsPermission: string implements PermissionEnum
{
    #[PermissionMeta(guards: [])]
    case BROKEN = 'broken:case';
}
