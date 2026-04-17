<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\PolicyStore;

/**
 * Stub `PolicyStore` implementation used to verify that a bound
 * store is resolved through the singleton container after the
 * service provider wires it up.
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
    /**
     * Return an empty policy list — the stub exists only to verify
     * the binding, not to drive evaluation.
     *
     * @param  object  $principal
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public function policiesFor(object $principal): array
    {
        return [];
    }
}
