<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;

/**
 * Stub provider that contributes guard-agnostic permissions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubNullGuardProvider implements PermissionProvider
{
    /**
     * Return the permission strings this provider contributes.
     *
     * @return array<int, string>
     */
    public function permissions(): array
    {
        return ['billing:view'];
    }

    /**
     * Return the guard name these permissions are scoped to.
     *
     * @return string|null
     */
    public function guard(): ?string
    {
        return null;
    }
}
