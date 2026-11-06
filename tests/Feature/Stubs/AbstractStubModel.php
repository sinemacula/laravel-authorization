<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;

/**
 * An abstract Eloquent model, which names no type a resource can be of, since
 * no record of it can exist.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class AbstractStubModel extends Model {}
