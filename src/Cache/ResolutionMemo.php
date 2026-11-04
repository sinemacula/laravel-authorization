<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

use Illuminate\Support\Carbon;

/**
 * The in-memory tier of the resolution cache.
 *
 * Holds each resolved list with the instant it lapses, so a temporal grant
 * stops being served at the same point in a long request, job or command as it
 * does from the persistent tier. The memo lives as long as the resolution cache
 * that owns it, which the service provider binds per request or job.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ResolutionMemo
{
    /** @var array<string, array{value: array<int, mixed>, expires_at: int|null}> Entries keyed by full cache key; `expires_at` is the timestamp the entry lapses at, null for never. */
    private array $entries = [];

    /**
     * Return the entry for the key, or null when there is none or it has
     * lapsed.
     *
     * @param  string  $key
     * @return array<int, mixed>|null
     */
    public function get(string $key): ?array
    {
        if (!isset($this->entries[$key]) || $this->lapsed($key)) {
            return null;
        }

        return $this->entries[$key]['value'];
    }

    /**
     * Determine whether the key holds an entry that has lapsed, as opposed to a
     * live entry or none at all.
     *
     * @param  string  $key
     * @return bool
     */
    public function lapsed(string $key): bool
    {
        $expiresAt = $this->entries[$key]['expires_at'] ?? null;

        return $expiresAt !== null && Carbon::now()->getTimestamp() >= $expiresAt;
    }

    /**
     * Store an entry that lapses the given number of seconds from now, or never
     * when the lifetime is null. A lifetime of zero or less stores an entry
     * that has already lapsed.
     *
     * @param  string  $key
     * @param  array<int, mixed>  $value
     * @param  int|null  $lifetime
     * @return void
     */
    public function put(string $key, array $value, ?int $lifetime): void
    {
        $this->entries[$key] = [
            'value'      => $value,
            'expires_at' => $lifetime === null ? null : Carbon::now()->getTimestamp() + $lifetime,
        ];
    }

    /**
     * Drop the entry for the key.
     *
     * @param  string  $key
     * @return void
     */
    public function forget(string $key): void
    {
        unset($this->entries[$key]);
    }

    /**
     * Drop every entry.
     *
     * @return void
     */
    public function flush(): void
    {
        $this->entries = [];
    }
}
