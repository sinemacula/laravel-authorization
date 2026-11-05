<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Contracts\Cache\Store;

/**
 * A cache store that fails on every operation, as a client does when its
 * backend is unreachable, counting the operations it was asked for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FailingCacheStore implements Store
{
    /** @var int The operations the store was asked for. */
    public int $calls = 0;

    /**
     * @param  mixed  $key
     * @return mixed
     */
    #[\Override]
    public function get(mixed $key): mixed
    {
        return $this->fail();
    }

    /**
     * @param  array<int, string>  $keys
     * @return array<string, mixed>
     *
     * @phpstan-ignore method.childParameterType
     */
    #[\Override]
    public function many(array $keys): array
    {
        return $this->fail();
    }

    /**
     * @imperative
     *
     * @param  mixed  $key
     * @param  mixed  $value
     * @param  mixed  $seconds
     * @return bool
     */
    #[\Override]
    public function put(mixed $key, mixed $value, mixed $seconds): bool
    {
        return $this->fail();
    }

    /**
     * @imperative
     *
     * @param  array<string, mixed>  $values
     * @param  mixed  $seconds
     * @return bool
     *
     * @phpstan-ignore method.childParameterType
     */
    #[\Override]
    public function putMany(array $values, mixed $seconds): bool
    {
        return $this->fail();
    }

    /**
     * @param  mixed  $key
     * @param  mixed  $value
     * @return bool|int
     */
    #[\Override]
    public function increment(mixed $key, mixed $value = 1): bool|int
    {
        return $this->fail();
    }

    /**
     * @param  mixed  $key
     * @param  mixed  $value
     * @return bool|int
     */
    #[\Override]
    public function decrement(mixed $key, mixed $value = 1): bool|int
    {
        return $this->fail();
    }

    /**
     * @imperative
     *
     * @param  mixed  $key
     * @param  mixed  $value
     * @return bool
     */
    #[\Override]
    public function forever(mixed $key, mixed $value): bool
    {
        return $this->fail();
    }

    /**
     * The store contract only declares `touch()` from Laravel 13, so the
     * override attribute is omitted to keep the stub loadable on Laravel 12.
     *
     * @imperative
     *
     * @param  mixed  $key
     * @param  mixed  $ttl
     * @return bool
     *
     * @phpstan-ignore-next-line method.missingOverride
     */
    public function touch(mixed $key, mixed $ttl): bool
    {
        return $this->fail();
    }

    /**
     * @imperative
     *
     * @param  mixed  $key
     * @return bool
     */
    #[\Override]
    public function forget(mixed $key): bool
    {
        return $this->fail();
    }

    /**
     * @imperative
     *
     * @return bool
     */
    #[\Override]
    public function flush(): bool
    {
        return $this->fail();
    }

    /**
     * @return string
     */
    #[\Override]
    public function getPrefix(): string
    {
        return '';
    }

    /**
     * Count the operation and fail it.
     *
     * @return never
     *
     * @throws \RuntimeException
     */
    private function fail(): never
    {
        $this->calls++;

        throw new \RuntimeException('cache unavailable');
    }
}
