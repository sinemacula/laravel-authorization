<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;

/**
 * Stub provider that contributes two permissions under the `web` guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
final class StubPermissionProvider implements PermissionProvider
{
    /**
     * Return the permission strings this provider contributes.
     *
     * @return array<int, string>
     */
    public function permissions(): array
    {
        return ['media:upload', 'media:delete'];
    }

    /**
     * Return the guard name these permissions are scoped to.
     *
     * @return string|null
     */
    public function guard(): ?string // @phpstan-ignore return.unusedType (stub returns non-null)
    {
        return 'web';
    }
}
