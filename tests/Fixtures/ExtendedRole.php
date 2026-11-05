<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Consumer-style subclass of the shipped `Role` model.
 *
 * Extends the system-protection boot hook, as a consuming application's model
 * may, and gives the tests a subclass scope to run the guard from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExtendedRole extends Role
{
    /**
     * Register the inherited system-protection hooks.
     *
     * @return void
     */
    #[\Override]
    protected static function bootHasSystemProtection(): void
    {
        parent::bootHasSystemProtection();
    }
}
