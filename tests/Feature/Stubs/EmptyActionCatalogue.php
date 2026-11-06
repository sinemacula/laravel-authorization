<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;

/**
 * An action catalogue for tests that covers no pattern, not even `*`: one that
 * declares no action at all, as the declared catalogue never is, since the
 * package declares its own permissions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EmptyActionCatalogue implements ActionCatalogue
{
    /**
     * Cover no pattern.
     *
     * @param  string  $pattern
     * @return bool
     */
    #[\Override]
    public function covers(string $pattern): bool
    {
        return false;
    }
}
