<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * Application-side subclass of the shipped `Permission` model, registered under
 * `authorization.models.permission` to prove the package uses the configured
 * class.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CustomPermission extends Permission {}
