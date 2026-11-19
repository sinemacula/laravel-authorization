<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\PolicyStore;

/**
 * Stub `PolicyStore` implementation used to verify that a bound store is
 * resolved through the singleton container after the service provider wires it
 * up, and that a store's answer is read on every check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
final class StubPolicyStore implements PolicyStore
{
    /** @var array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy> The policies returned for every principal. */
    public array $policies = [];

    /**
     * Return the policies the stub holds, none unless a test sets them.
     *
     * @param  object  $principal
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    #[\Override]
    public function policiesFor(object $principal): array
    {
        return $this->policies;
    }
}
