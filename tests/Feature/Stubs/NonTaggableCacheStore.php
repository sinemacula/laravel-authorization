<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Contracts\Cache\Store;

/**
 * In-memory, non-taggable cache store used by resolution-cache tests.
 *
 * Mirrors the minimum surface of the shipped File / Database drivers that
 * Laravel's `Repository` wraps unchanged. The absence of a `tags()` method
 * means `ResolutionCache::isTaggable()` reports false, exercising the non-tag
 * code branches in the cache layer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class NonTaggableCacheStore implements Store
{
    /** @var array<string, mixed> */
    public array $storage = [];

    /**
     * @param  mixed  $key
     * @return mixed
     */
    public function get(mixed $key): mixed
    {
        return $this->storage[$key] ?? null; // @phpstan-ignore offsetAccess.invalidOffset
    }

    /**
     * @param  array<int, string>  $keys
     * @return array<string, mixed>
     */
    public function many(array $keys): array // @phpstan-ignore method.childParameterType
    {
        $cachedEntries = [];

        foreach ($keys as $key) {
            $cachedEntries[$key] = $this->storage[$key] ?? null;
        }

        return $cachedEntries;
    }

    /**
     * @param  mixed  $key
     * @param  mixed  $value
     * @param  mixed  $seconds
     * @return bool
     */
    public function put(mixed $key, mixed $value, mixed $seconds): bool
    {
        $this->storage[$key] = $value; // @phpstan-ignore offsetAccess.invalidOffset

        return true;
    }

    /**
     * @param  array<string, mixed>  $values
     * @param  mixed  $seconds
     * @return bool
     */
    public function putMany(array $values, mixed $seconds): bool // @phpstan-ignore method.childParameterType
    {
        foreach ($values as $key => $value) {
            $this->storage[$key] = $value;
        }

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
        $this->storage[$key] = $value; // @phpstan-ignore offsetAccess.invalidOffset

        return true;
    }

    /**
     * @param  mixed  $key
     * @param  mixed  $ttl
     * @return bool
     */
    public function touch(mixed $key, mixed $ttl): bool
    {
        return isset($this->storage[$key]); // @phpstan-ignore offsetAccess.invalidOffset
    }

    /**
     * @param  mixed  $key
     * @return bool
     */
    public function forget(mixed $key): bool
    {
        unset($this->storage[$key]); // @phpstan-ignore offsetAccess.invalidOffset

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
