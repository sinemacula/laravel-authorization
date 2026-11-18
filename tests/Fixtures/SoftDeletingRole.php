<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Illuminate\Database\Eloquent\SoftDeletes;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * The soft-deleting role subclass the model extension guide describes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SoftDeletingRole extends Role
{
    use SoftDeletes;
}
