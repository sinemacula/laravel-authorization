<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

/**
 * Holds the key of the scope a test is in, which the test moves between scopes
 * by changing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScopeKeyHolder
{
    /**
     * Create a new holder of the scope key.
     *
     * @param  string  $key
     */
    public function __construct(

        /** The key of the current scope. */
        public string $key = 'tenant-a',
    ) {}
}
