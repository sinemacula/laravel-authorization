<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

/**
 * A Laravel policy class that refuses every ability on its model, whatever its
 * name, as a policy method for each would, so a test can show which abilities
 * the package answers before the policy is consulted and which fall through to
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DenyingLaravelPolicy
{
    /**
     * Answer the ability the method is named after.
     *
     * @param  string  $method
     * @param  array<int, mixed>  $arguments
     * @return bool
     */
    public function __call(string $method, array $arguments): bool
    {
        return false;
    }
}
