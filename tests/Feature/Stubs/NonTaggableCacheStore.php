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
    #[\Override]
    public function get(mixed $key): mixed
    {
        return $this->storage[$key] ?? null; // @phpstan-ignore offsetAccess.invalidOffset
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
        $cachedEntries = [];

        foreach ($keys as $key) {
            $cachedEntries[$key] = $this->storage[$key] ?? null;
        }

        return $cachedEntries;
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
        $this->storage[$key] = $value; // @phpstan-ignore offsetAccess.invalidOffset

        return true;
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
    #[\Override]
    public function increment(mixed $key, mixed $value = 1): bool|int
    {
        return false;
    }

    /**
     * @param  mixed  $key
     * @param  mixed  $value
     * @return bool|int
     */
    #[\Override]
    public function decrement(mixed $key, mixed $value = 1): bool|int
    {
        return false;
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
        $this->storage[$key] = $value; // @phpstan-ignore offsetAccess.invalidOffset

        return true;
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
        return isset($this->storage[$key]); // @phpstan-ignore offsetAccess.invalidOffset
    }

    /**
     * @param  mixed  $key
     * @return bool
     */
    #[\Override]
    public function forget(mixed $key): bool
    {
        unset($this->storage[$key]); // @phpstan-ignore offsetAccess.invalidOffset

        return true;
    }

    /**
     * @return bool
     */
    #[\Override]
    public function flush(): bool
    {
        $this->storage = [];

        return true;
    }

    /**
     * @return string
     */
    #[\Override]
    public function getPrefix(): string
    {
        return '';
    }
}
