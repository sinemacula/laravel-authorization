<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Application-side subclass of the shipped `Role` model, registered under
 * `authorization.models.role` to prove the package uses the configured class.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CustomRole extends Role {}
