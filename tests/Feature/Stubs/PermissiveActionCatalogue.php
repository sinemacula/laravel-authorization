<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;

/**
 * An action catalogue for tests that covers every pattern, so a test can write
 * a policy naming any action without declaring it first.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PermissiveActionCatalogue implements ActionCatalogue
{
    /**
     * Cover every pattern.
     *
     * @param  string  $pattern
     * @return bool
     */
    #[\Override]
    public function covers(string $pattern): bool
    {
        return true;
    }
}
