<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;

/**
 * Stub provider that counts how often its permissions are read, so a test can
 * show that booting never reads them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingPermissionProvider implements PermissionProvider
{
    /** @var int How many times the permissions were read. */
    public static int $reads = 0;

    /**
     * Return the permission strings this provider contributes.
     *
     * @return array<int, string>
     */
    #[\Override]
    public function permissions(): array
    {
        self::$reads++;

        return ['reports:export'];
    }

    /**
     * Return the guard name these permissions are scoped to.
     *
     * @return string|null
     */
    #[\Override]
    public function guard(): ?string
    {
        return null;
    }
}
