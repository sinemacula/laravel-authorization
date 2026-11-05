<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;

/**
 * Stub provider that declares two `web` permissions with metadata and one
 * guard-agnostic permission without.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubPermissionProvider implements PermissionProvider
{
    /**
     * Return the permissions this provider declares.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>
     */
    #[\Override]
    public function permissions(): array
    {
        return [
            new PermissionDefinition(name: 'media:upload', description: 'Upload media', category: 'Media', guard: 'web'),
            new PermissionDefinition(name: 'media:delete', description: 'Delete media', category: 'Media', guard: 'web'),
            new PermissionDefinition(name: 'billing:view'),
        ];
    }
}
