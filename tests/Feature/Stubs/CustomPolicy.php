<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * Application-side subclass of the shipped `Policy` model, registered under
 * `authorization.models.policy` to prove the package uses the configured class.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CustomPolicy extends Policy {}
