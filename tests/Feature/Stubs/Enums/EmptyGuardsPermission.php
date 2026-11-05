<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs\Enums;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum as PermissionEnumContract;

/**
 * Permission enum whose case lists no guards, which declares nothing and is
 * refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum EmptyGuardsPermission: string implements PermissionEnumContract
{
    #[PermissionMeta(description: 'Export reports', guards: [])]
    case REPORTS_EXPORT = 'reports:export';
}
