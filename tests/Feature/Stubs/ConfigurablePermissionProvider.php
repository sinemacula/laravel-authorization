<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;

/**
 * Stub provider returning whatever a test sets, so each test can declare the
 * catalogue it needs, malformed entries included.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConfigurablePermissionProvider implements PermissionProvider
{
    /** @var array<int, mixed> What `permissions()` returns. */
    public static array $permissions = [];

    /**
     * Return the permissions the test set.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>
     */
    #[\Override]
    public function permissions(): array
    {
        /** @var list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition> */
        return self::$permissions;
    }
}
