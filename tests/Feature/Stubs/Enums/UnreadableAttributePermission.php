<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs\Enums;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum as PermissionEnumContract;

/**
 * Permission enum whose cases carry a `#[Permission]` attribute that cannot be
 * instantiated: one repeated, one given an argument of the wrong type.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum UnreadableAttributePermission: string implements PermissionEnumContract
{
    #[PermissionMeta(description: 'First')]
    #[PermissionMeta(description: 'Second')] // @phpstan-ignore attribute.nonRepeatable
    case REPEATED = 'reports:repeated';

    #[PermissionMeta(description: 1)] // @phpstan-ignore argument.type
    case WRONG_TYPE = 'reports:wrong';
}
