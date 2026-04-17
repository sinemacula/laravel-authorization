<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Contracts\Cache\Store;

/**
 * Non-taggable cache store whose `get()` always throws.
 *
 * Used to drive the corrupt-entry recovery path in
 * `ResolutionCache::rememberStringList`, which must tolerate a
 * driver that raises on read and fall back to the resolver.
 * `getCalls` / `forgetCalls` counters let the caller assert that
 * both the read attempt and the subsequent cleanup ran.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S112")
 */
final class ThrowingGetCacheStore implements Store
{
    /** @var array<string, mixed> */
    public array $storage = [];

    /** @var int */
    public int $getCalls = 0;

    /** @var int */
    public int $forgetCalls = 0;

    /**
     * @param  mixed  $key
     * @return mixed
     *
     * @throws \RuntimeException
     */
    public function get(mixed $key): mixed
    {
        $this->getCalls++;

        throw new \RuntimeException('transient driver failure');
    }

    /**
     * @param  array<int, string>  $keys
     * @return array<string, mixed>
     */
    public function many(array $keys): array // @phpstan-ignore method.childParameterType (stub narrows parameter type)
    {
        return [];
    }

    /**
     * @param  mixed  $key
     * @param  mixed  $value
     * @param  mixed  $seconds
     * @return bool
     */
    public function put(mixed $key, mixed $value, mixed $seconds): bool
    {
        $this->storage[$key] = $value; // @phpstan-ignore offsetAccess.invalidOffset (known array key from fixture)

        return true;
    }

    /**
     * @param  array<string, mixed>  $values
     * @param  mixed  $seconds
     * @return bool
     */
    public function putMany(array $values, mixed $seconds): bool // @phpstan-ignore method.childParameterType (stub narrows parameter type)
    {
        return true;
    }

    /**
     * @param  mixed  $key
     * @param  mixed  $value
     * @return bool|int
     */
    public function increment(mixed $key, mixed $value = 1): bool|int
    {
        return false;
    }

    /**
     * @param  mixed  $key
     * @param  mixed  $value
     * @return bool|int
     */
    public function decrement(mixed $key, mixed $value = 1): bool|int
    {
        return false;
    }

    /**
     * @param  mixed  $key
     * @param  mixed  $value
     * @return bool
     */
    public function forever(mixed $key, mixed $value): bool
    {
        $this->storage[$key] = $value; // @phpstan-ignore offsetAccess.invalidOffset (known array key from fixture)

        return true;
    }

    /**
     * @param  mixed  $key
     * @param  mixed  $ttl
     * @return bool
     */
    public function touch(mixed $key, mixed $ttl): bool
    {
        return true;
    }

    /**
     * @param  mixed  $key
     * @return bool
     */
    public function forget(mixed $key): bool
    {
        $this->forgetCalls++;
        unset($this->storage[$key]); // @phpstan-ignore offsetAccess.invalidOffset (known array key from fixture)

        return true;
    }

    /**
     * @return bool
     */
    public function flush(): bool
    {
        $this->storage = [];

        return true;
    }

    /**
     * @return string
     */
    public function getPrefix(): string
    {
        return '';
    }
}
