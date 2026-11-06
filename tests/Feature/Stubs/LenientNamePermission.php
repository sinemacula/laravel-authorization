<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * A permission model accepting any non-empty name, so a test can declare a
 * permission whose name holds characters `fnmatch` reads as a pattern.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LenientNamePermission extends Permission
{
    /**
     * Accept any non-empty string as a name.
     *
     * @param  mixed  $value
     * @return bool
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    #[\Override]
    public static function isValidAuthorizationName(mixed $value): bool
    {
        return \is_string($value) && $value !== '';
    }
}
