<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * A policy model, registered under `authorization.models.policy`, that finds no
 * policy by its key, since it keys its rows by name: once it is registered,
 * every policy the package reads by key is gone, as one deleted from under a
 * row that names it would be, which the foreign keys never let happen.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class VanishedPolicy extends Policy
{
    /** @var string The column the model is keyed by. */
    protected $primaryKey = 'name';
}
