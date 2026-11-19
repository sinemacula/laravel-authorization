<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Support\AuthorizationLog;

/**
 * Reads and keeps the resolution cache's entries across its two tiers: a stored
 * entry read back into the memo, and a resolution kept in the memo and in the
 * store (see `ResolutionCache`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ResolutionTiers
{
    /** @var string The prefix of the memo key the routes behind an entry are kept under. */
    public const string ROUTES = 'routes:';

    /** @var string The prefix of the memo key the break-glass activations behind an entry are kept under. */
    public const string ACTIVATIONS = 'activations:';

    /** @var list<string> The kinds of entry the break-glass activations behind them are kept beside. */
    private const array ATTRIBUTED = ['permissions', 'policies', 'role-keys'];

    /** @var string The prefix of every persistent entry's key: the namespace, with the break-glass state it was built in. */
    private string $entries;

    /** @var list<string> The kinds, as kept, the break-glass activations behind an entry are kept beside; none while break-glass is disabled. */
    private array $attributed;

    /**
     * Create a new pair of tiers.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionMemo  $memo
     * @param  \SineMacula\Laravel\Authorization\Cache\VersionedStore|null  $store
     * @param  string  $prefix
     * @param  int  $ttl
     * @param  bool  $isTrackingUsage
     * @param  bool  $isBreakGlassEnabled
     */
    public function __construct(

        /** In-memory tier, keyed by full cache key. */
        private ResolutionMemo $memo,

        /** Persistent tier; null keeps the memo only. */
        private ?VersionedStore $store,

        // Namespace prefix for every key written by the cache.
        string $prefix,

        /** The longest any entry lives, in seconds. */
        private int $ttl,

        // Whether grant usage is tracked, which renames the kinds kept with
        // routes.
        bool $isTrackingUsage,

        // Whether break-glass is enabled for the request or job.
        bool $isBreakGlassEnabled,
    ) {
        $this->entries = $isBreakGlassEnabled ? $prefix . ':break-glass' : $prefix;

        $this->attributed = $isBreakGlassEnabled
            ? \array_map(static fn (string $kind): string => ResolutionCodec::kindOf($kind, $isTrackingUsage), self::ATTRIBUTED)
            : [];
    }

    /**
     * Return the key of the persistent entry of the kind for the grantee.
     *
     * @param  string  $kind
     * @param  object  $grantee
     * @return string
     */
    public function key(string $kind, object $grantee): string
    {
        return PrincipalCacheKey::entry($this->entries, $kind, $grantee);
    }

    /**
     * Keep what a resolution found as the entry of the kind for the grantee, in
     * the memo, and in the store when the grantee has a key and nothing it read
     * changed as it ran, for no longer than the configured maximum, or a second
     * before the nearest expiry of a grant it counts, and return it. Given the
     * writes of a bulk read, the entry is added to them, under its lifetime, to
     * be written with the rest at once, rather than written now.
     *
     * @template TValue
     *
     * @param  string  $kind
     * @param  object  $grantee
     * @param  \SineMacula\Laravel\Authorization\Cache\Resolution<TValue>  $resolution
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionPins  $pins
     * @param  bool  $held
     * @param  (\Closure(TValue): mixed)|null  $encode
     * @param  array<int, array<string, array<string, mixed>>>|null  $writes
     *
     * @param-out ($writes is null ? null : array<int, array<string, array<string, mixed>>>) $writes
     *
     * @return list<TValue>
     */
    public function keep(string $kind, object $grantee, Resolution $resolution, ResolutionPins $pins, bool $held, ?\Closure $encode, ?array &$writes = null): array
    {
        $lifetime = $resolution->expiresIn === null ? $this->ttl : \min($this->ttl, $resolution->expiresIn - 1);
        $memoKey  = $kind . ':' . PrincipalCacheKey::for($grantee);

        $this->memo->put($memoKey, $resolution->value, $lifetime);

        if ($resolution->routes !== null) {
            $this->memo->put(self::ROUTES . $memoKey, [$resolution->routes], $lifetime);
        }

        $this->keepActivations($memoKey, $resolution->activations);

        if ($this->store === null || !$resolution->stable || !$held || !$pins->isComplete()) {
            return $resolution->value;
        }

        if (PrincipalCacheKey::isKeyless($grantee)) {
            return $resolution->value;
        }

        $key   = $this->key($kind, $grantee);
        $entry = [
            'versions' => $pins->tokens(),
            'value'    => $encode === null ? $resolution->value : \array_map($encode, $resolution->value),
            'until'    => Carbon::now()->getTimestamp() + $lifetime,
            ...ResolutionCodec::encodeRoutes($resolution->routes),
            ...($resolution->activations === [] ? [] : ['activations' => $resolution->activations]),
        ];

        if ($writes === null) {
            $this->store->put($key, $entry, $lifetime);
        } else {
            $writes[$lifetime][$key] = $entry;
        }

        return $resolution->value;
    }

    /**
     * Return the stored entry's value, memoised for the rest of its life, or
     * null when there is none, it has lapsed, a version it recorded has
     * changed, or it cannot be read back. Given the entries a bulk read found,
     * whose versions it has checked, the entry is taken from those, without
     * reading the store again.
     *
     * @param  string  $memoKey
     * @param  string  $key
     * @param  \Closure(array<mixed>): list<mixed>  $decode
     * @param  array<string, array{versions: array<string, string>, value: array<mixed>, until: int}>|null  $entries
     * @return list<mixed>|null
     */
    public function read(string $memoKey, string $key, \Closure $decode, ?array $entries = null): ?array
    {
        if ($this->store === null) {
            return null;
        }

        $entry = $entries === null ? $this->store->get($key) : $entries[$key] ?? null;

        if (!self::isServable($this->store, $entry, $entries !== null)) {
            return null;
        }

        try {
            $value       = $decode($entry['value']);
            $routes      = \array_key_exists('routes', $entry) ? ResolutionCodec::routes($entry['routes']) : null;
            $activations = ResolutionCodec::activations($entry['activations'] ?? []);
        } catch (\Throwable $exception) {
            AuthorizationLog::warning("Authorization: discarding corrupt resolution-cache entry '{$key}' — " . $exception->getMessage(), [
                'cache_key' => $key,
                'reason'    => $exception->getMessage(),
            ]);

            $value       = null;
            $routes      = null;
            $activations = [];
        }

        if ($value !== null) {
            $this->memo->put($memoKey, $value, $entry['until'] - Carbon::now()->getTimestamp());
            $this->keepActivations($memoKey, $activations);
        }

        if ($value !== null && $routes !== null) {
            $this->memo->put(self::ROUTES . $memoKey, [$routes], $entry['until'] - Carbon::now()->getTimestamp());
        }

        return $value;
    }

    /**
     * Keep the break-glass activations behind the entry beside it in the memo,
     * for a kind they are asked about while break-glass is enabled, none
     * included, so a list kept before is replaced.
     *
     * @param  string  $memoKey
     * @param  array<string, list<string>>  $activations
     * @return void
     */
    private function keepActivations(string $memoKey, array $activations): void
    {
        if (!\in_array(\strstr($memoKey, ':', true), $this->attributed, true)) {
            return;
        }

        $this->memo->put(self::ACTIVATIONS . $memoKey, [$activations], null);
    }

    /**
     * Determine whether a stored entry may be served: well formed, not yet
     * lapsed, and holding every version it recorded unless those are checked.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\VersionedStore  $store
     * @param  mixed  $entry
     * @param  bool  $isChecked
     * @return bool
     *
     * @phpstan-assert-if-true array{versions: non-empty-array<string, string>, value: array<mixed>, until: int, routes?: mixed, activations?: mixed} $entry
     */
    private static function isServable(VersionedStore $store, mixed $entry, bool $isChecked): bool
    {
        if (!ResolutionCodec::isEntry($entry) || $entry['until'] <= Carbon::now()->getTimestamp()) {
            return false;
        }

        return $isChecked || $store->tokens(\array_keys($entry['versions'])) === $entry['versions'];
    }
}
