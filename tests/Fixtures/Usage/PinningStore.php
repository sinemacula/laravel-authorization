<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Usage;

use Illuminate\Cache\ArrayStore;

/**
 * An array store that runs a callback every time versions are read, as a
 * resolution pins them, so a test can change the data a resolution reads while
 * it runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PinningStore extends ArrayStore
{
    /**
     * Create a new pinning store.
     *
     * @param  \Closure(array<mixed>): void  $onPin
     */
    public function __construct(

        /** The callback run on every pin. */
        private readonly \Closure $onPin,
    ) {
        parent::__construct();
    }

    /**
     * Run the callback, then read the versions.
     *
     * @param  array<mixed>  $keys
     * @return array<string, mixed>
     */
    #[\Override]
    public function many(array $keys): array
    {
        ($this->onPin)($keys);

        return parent::many($keys);
    }
}
