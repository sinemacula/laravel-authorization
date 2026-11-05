<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;

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
     * Return the permissions this provider declares.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>
     */
    #[\Override]
    public function permissions(): array
    {
        self::$reads++;

        return [new PermissionDefinition(name: 'reports:export')];
    }
}
