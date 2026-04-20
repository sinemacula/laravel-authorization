<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\PermissionEnum as PermissionEnumContract;

/**
 * Malformed permission enum used to assert that the config validator
 * rejects backed int enums — the interface permits backed enums but
 * the validator requires the string backing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum IntBackedPermissionEnum: int implements PermissionEnumContract
{
    case PostsCreate = 1;
    case PostsDelete = 2;
}
