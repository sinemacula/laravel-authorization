<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs\Contracts;

use SineMacula\Laravel\Authorization\Contracts\PermissionEnum as PermissionEnumContract;

/**
 * Interface extending the permission enum contract, which the config validation
 * refuses because it is not an enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface PermissionEnumInterface extends PermissionEnumContract {}
