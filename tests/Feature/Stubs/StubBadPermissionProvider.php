<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;

/**
 * Stub `PermissionProvider` that returns an empty string and a non-string value
 * — the service provider must skip both without raising, and without creating
 * database rows for them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubBadPermissionProvider implements PermissionProvider
{
    /**
     * Return a mix of empty, non-string, and well-formed permissions.
     *
     * @return array<int, mixed>
     *
     * @phpstan-ignore method.childReturnType
     */
    #[\Override]
    public function permissions(): array
    {
        return ['', 42, 'valid:perm'];
    }

    /**
     * Return the guard name associated with this provider.
     *
     * @return string|null
     *
     * @phpstan-ignore return.unusedType
     */
    #[\Override]
    public function guard(): ?string
    {
        return 'web';
    }
}
