<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Cache\ArrayStore;

/**
 * An array store that, while it refuses, reports every write as failed by
 * returning false rather than throwing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RefusingCacheStore extends ArrayStore
{
    /** @var bool Whether the store refuses writes. */
    public bool $refuses = true;

    /**
     * @imperative
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  int  $seconds
     * @return bool
     */
    #[\Override]
    public function put(mixed $key, mixed $value, mixed $seconds): bool
    {
        return !$this->refuses && parent::put($key, $value, $seconds);
    }
}
