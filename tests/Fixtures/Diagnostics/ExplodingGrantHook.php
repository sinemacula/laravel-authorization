<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Diagnostics;

use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Hooks\GrantWidening;

/**
 * A grant hook that explodes when it is built or called (see `Explosions`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExplodingGrantHook implements GrantHook
{
    /**
     * Explode.
     */
    public function __construct()
    {
        Explosions::explode();
    }

    /**
     * Explode.
     *
     * @param  \SineMacula\Laravel\Authorization\Hooks\GrantWidening  $widening
     * @return void
     */
    #[\Override]
    public function beforeWidening(GrantWidening $widening): void
    {
        Explosions::explode();
    }
}
