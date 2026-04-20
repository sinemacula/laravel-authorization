<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Traits\HasContainerInstance;

/**
 * Two-tier cache (in-memory memo plus optional persistent store) for principal
 * resolution lookups — roles, permissions, and hydrated policies. Invalidation
 * is event-driven via listener calls to `forget()` / `forgetRoleTags()` /
 * `flush()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ResolutionCache
{
    use HasContainerInstance;

    /** @var array<string, mixed> In-memory memo keyed by full cache key. */
    private array $memo = [];

    /** @var bool|null Cached taggable capability flag; null until probed. */
    private ?bool $taggable = null;

    /**
     * Create a new cache instance.
     *
     * @param  \Illuminate\Contracts\Cache\Repository|null  $store
     * @param  int  $ttl
     * @param  string  $prefix
     */
    public function __construct(

        /** Optional persistent cache store; null disables cross-request. */
        private readonly ?CacheRepository $store = null,

        /** Entry lifetime in seconds; 0 stores forever. @infection-ignore-all DecrementInteger */
        private readonly int $ttl = 0,

        /** Namespace prefix for every key written by this cache. */
        private readonly string $prefix = 'authorization',

    ) {}

    /**
     * Return the cached list of policies for the principal, or invoke the
     * resolver and cache its output.
     *
     * @param  object  $principal
     * @param  \Closure(): array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $resolver
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext|null  $context
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public function rememberPolicies(object $principal, \Closure $resolver, ?ResolutionCacheContext $context = null): array
    {
        $context ??= new ResolutionCacheContext;
        $key = $this->key('policies', $principal);

        if (array_key_exists($key, $this->memo)) {
            /** @var array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy> */
            return $this->memo[$key];
        }

        $cached = $this->readCachedPolicies($key, $principal, $context->roleIds);

        if ($cached !== null) {
            return $this->memo[$key] = $cached;
        }

        /** @var array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy> $policies */
        $policies         = $resolver();
        $this->memo[$key] = $policies;

        if ($this->store !== null) {
            $documents = array_map(static fn (Policy $policy): array => $policy->toArray(), $policies);
            $this->putInStore($key, $documents, $principal, $context->roleIds, $context->maxTtl);
        }

        return $policies;
    }

    /**
     * Drop every cached entry for the supplied principal — memo and persistent
     * store alike. Listeners call this on principal-scoped mutations
     * (`IdentityRoleAssigned`, `IdentityPermissionGranted`,
     * `IdentityPolicyAttached`, and their inverses).
     *
     * On a tag-capable store the principal tag flushes every slot in one call;
     * non-tagged stores fall back to per-slot `forget()`.
     *
     * @param  object  $principal
     * @return void
     */
    public function forget(object $principal): void
    {
        foreach (['policies', 'permissions', 'roles'] as $kind) {
            $key = $this->key($kind, $principal);
            unset($this->memo[$key]);
        }

        if ($this->store === null) {
            return;
        }

        if ($this->isTaggable()) {

            /** @var \Illuminate\Contracts\Cache\Repository $store */
            $store = $this->store;

            // @phpstan-ignore-next-line method.notFound
            $store->tags([$this->principalTag($principal)])->flush();

            return;
        }

        foreach (['policies', 'permissions', 'roles'] as $kind) {
            $this->store->forget($this->key($kind, $principal));
        }
    }

    /**
     * Drop every in-memory entry. Listeners call this on role pivot changes
     * (`RolePermissionGranted` / `RolePermissionRevoked`) on non-tag stores,
     * where the cache holds no reverse index from role to the identities
     * carrying it. Tag-capable stores use `forgetRoleTags()` instead and leave
     * the memo of other principals alone.
     *
     * @return void
     */
    public function flush(): void
    {
        // Persistent store is not cleared here because flushing the entire
        // configured cache would wipe unrelated entries — the per-request memo
        // reset is the practical safety net on non-tag stores; tag-capable
        // stores use `forgetRoleTags()` for precise per-role invalidation.
        $this->memo = [];
    }

    /**
     * Return the cached permission-name list for the principal, or invoke the
     * resolver and cache its output.
     *
     * @param  object  $principal
     * @param  \Closure(): array<int, string>  $resolver
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext|null  $context
     * @return array<int, string>
     */
    public function rememberPermissions(object $principal, \Closure $resolver, ?ResolutionCacheContext $context = null): array
    {
        $context ??= new ResolutionCacheContext;

        return $this->rememberStringList('permissions', $principal, $resolver, $context->maxTtl, $context->roleIds);
    }

    /**
     * Return the cached role-name list for the principal, or invoke the
     * resolver and cache its output.
     *
     * @param  object  $principal
     * @param  \Closure(): array<int, string>  $resolver
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext|null  $context
     * @return array<int, string>
     */
    public function rememberRoles(object $principal, \Closure $resolver, ?ResolutionCacheContext $context = null): array
    {
        $context ??= new ResolutionCacheContext;

        return $this->rememberStringList('roles', $principal, $resolver, $context->maxTtl, $context->roleIds);
    }

    /**
     * Drop every persistent entry tagged for the supplied role.
     *
     * On a tag-capable store this is the precise inverse of
     * `RolePermissionGranted` / `RolePermissionRevoked` — every principal
     * carrying the role has its cached entries flushed via the role tag. On a
     * non-tag store the persistent tier cannot be targeted without a reverse
     * index, so the method is a no-op there — the listener is expected to pair
     * this call with `flush()` for the memo sweep.
     *
     * @param  object  $role
     * @return void
     */
    public function forgetRoleTags(object $role): void
    {
        if ($this->store === null || !$this->isTaggable()) {
            return;
        }

        /** @var mixed $raw */
        $raw = method_exists($role, 'getKey') ? $role->getKey() : null;
        $id  = (is_string($raw) || is_int($raw)) ? (string) $raw : '';

        if ($id === '') {
            return;
        }

        /** @var \Illuminate\Contracts\Cache\Repository $store */
        $store = $this->store;

        // @phpstan-ignore-next-line method.notFound
        $store->tags(["{$this->prefix}:role:{$id}"])->flush();
    }

    /**
     * Report whether the configured store exposes a `tags()` method. Exposed
     * for the listener to pick between the tag-based role invalidation path and
     * the in-memory fallback without probing the store itself.
     *
     * @return bool
     */
    public function supportsTags(): bool
    {
        return $this->isTaggable();
    }

    /**
     * Build the cache key for a given slot + principal.
     *
     * @param  string  $kind
     * @param  object  $principal
     * @return string
     */
    private function key(string $kind, object $principal): string
    {
        return "{$this->prefix}:{$kind}:" . $this->keyFor($principal);
    }

    /**
     * Derive the principal portion of the cache key.
     *
     * Eloquent models use their canonical `getMorphClass()` + `getKey()`
     * pairing. Non-Eloquent principals are duck-typed on those same accessors;
     * principals exposing neither fall back to a per-request
     * `spl_object_hash()`, in which case only the in-memory memo applies.
     *
     * @param  object  $principal
     * @return string
     */
    private function keyFor(object $principal): string
    {
        $type = $principal::class;
        $id   = null;

        if (method_exists($principal, 'getMorphClass')) {
            /** @var mixed $morph */
            $morph = $principal->getMorphClass();

            if (is_string($morph) && $morph !== '') {
                $type = $morph;
            }
        }

        if (method_exists($principal, 'getKey')) {
            /** @var mixed $raw */
            $raw = $principal->getKey();

            if (is_string($raw) || is_int($raw)) {
                $candidate = (string) $raw;

                if ($candidate !== '') {
                    $id = $candidate;
                }
            }
        }

        if ($id === null) {
            $id = 'obj:' . spl_object_hash($principal);
        }

        return "{$type}:{$id}";
    }

    /**
     * Attempt to hydrate cached policies from the persistent store, returning
     * null on miss or on a corrupt entry (which is forgotten and logged before
     * falling through).
     *
     * @param  string  $key
     * @param  object  $principal
     * @param  array<int, string>  $roleIds
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>|null
     */
    private function readCachedPolicies(string $key, object $principal, array $roleIds): ?array
    {
        if ($this->store === null) {
            return null;
        }

        try {

            /** @var mixed $raw */
            $raw = $this->readFromStore($key, $principal, $roleIds);

            if (!is_array($raw)) {
                return null;
            }

            $policies = [];

            foreach ($raw as $document) {

                if (!is_array($document)) {
                    throw new \UnexpectedValueException('Cached policy entry is not an array document.');
                }

                $policies[] = Policy::fromArray($document);
            }
        } catch (\Throwable $exception) {
            // Corrupt persistent-cache entry — forget the key, log through the
            // `authorization` channel, and let the caller fall through to the
            // fresh-read path.
            $this->forgetFromStore($key, $principal, $roleIds);
            $this->logCorruptCacheEntry($key, $exception);

            $policies = null;
        }

        return $policies;
    }

    /**
     * Read a key from the persistent store — routed through `tags()` on
     * tag-capable stores so reads hit the same namespace that `putInStore()`
     * wrote to.
     *
     * @param  string  $key
     * @param  object  $principal
     * @param  array<int, string>  $roleIds
     * @return mixed
     *
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    private function readFromStore(string $key, object $principal, array $roleIds): mixed
    {
        // @codeCoverageIgnoreStart
        // Defensive: every caller already checks `$this->store !== null` before
        // routing through here; the guard survives as a belt-and-braces for
        // future call sites.
        if ($this->store === null) {
            return null;
        }
        // @codeCoverageIgnoreEnd

        if ($this->isTaggable()) {

            /** @var \Illuminate\Contracts\Cache\Repository $store */
            $store = $this->store;

            // @phpstan-ignore-next-line method.notFound
            return $store->tags($this->tagsFor($principal, $roleIds))->get($key);
        }

        return $this->store->get($key);
    }

    /**
     * Probe (and cache) whether the configured store supports Laravel's
     * `tags()` fan-out. Laravel's `CacheManager` wraps every driver in a
     * `Repository` that exposes `tags()` unconditionally, so probing the
     * Repository itself gives a false positive for File / Database drivers that
     * throw `BadMethodCallException` on the call. The real capability marker is
     * on the bare driver: `TaggableStore` descendants (Redis, Memcached, the
     * array store) satisfy `method_exists($driver, 'tags')`, non-taggable
     * drivers do not. Probing via `getStore()` keeps the check working for any
     * future driver that opts in without a dedicated interface.
     *
     * @return bool
     */
    private function isTaggable(): bool
    {
        if ($this->store === null) {
            return false;
        }

        if ($this->taggable !== null) {
            return $this->taggable;
        }

        $driver = $this->store->getStore();

        return $this->taggable = method_exists($driver, 'tags');
    }

    /**
     * Compose the tag set for a cache entry — always includes the package-wide
     * tag and the principal tag, plus one tag per role ID the entry depends on.
     *
     * @param  object  $principal
     * @param  array<int, string>  $roleIds
     * @return array<int, string>
     */
    private function tagsFor(object $principal, array $roleIds): array
    {
        $tags = [$this->prefix, $this->principalTag($principal)];

        foreach ($roleIds as $id) {
            if ($id === '') {
                continue;
            }

            $tags[] = "{$this->prefix}:role:{$id}";
        }

        return array_values(array_unique($tags));
    }

    /**
     * Build the principal-scoped tag — used to flush every slot for a single
     * identity in one `tags()->flush()` call on tag-capable stores.
     *
     * @param  object  $principal
     * @return string
     */
    private function principalTag(object $principal): string
    {
        return "{$this->prefix}:principal:" . $this->keyFor($principal);
    }

    /**
     * Forget a corrupt key — mirrors `readFromStore()` so the tag-namespaced
     * entry is removed when the store is tag-capable.
     *
     * @param  string  $key
     * @param  object  $principal
     * @param  array<int, string>  $roleIds
     * @return void
     */
    private function forgetFromStore(string $key, object $principal, array $roleIds): void
    {
        // @codeCoverageIgnoreStart
        // Defensive: every caller already checks `$this->store !== null` before
        // routing through here.
        if ($this->store === null) {
            return;
        }
        // @codeCoverageIgnoreEnd

        // @codeCoverageIgnoreStart
        // The tag-capable branch fires only when the taggable driver's get()
        // itself raises — a corrupt-payload shape covered by a real
        // persistent-tier driver in production. The
        // `Illuminate\Cache\Repository` public API does not let a test assemble
        // an anonymous `TaggedCache` without duplicating large swathes of the
        // framework.
        if ($this->isTaggable()) {
            /** @var \Illuminate\Contracts\Cache\Repository $store */
            $store = $this->store;
            // @phpstan-ignore-next-line method.notFound
            $store->tags($this->tagsFor($principal, $roleIds))->forget($key);

            return;
        }
        // @codeCoverageIgnoreEnd

        $this->store->forget($key);
    }

    /**
     * Report a corrupt persistent-cache entry without raising — the caller has
     * already forgotten the key and will recompute via the resolver, so the
     * cache self-heals on the same request.
     *
     * @param  string  $key
     * @param  \Throwable  $exception
     * @return void
     */
    private function logCorruptCacheEntry(string $key, \Throwable $exception): void
    {
        // @codeCoverageIgnoreStart
        // Defensive: the Laravel `logger()` helper is always present under a
        // booted framework, so this fallback is reachable only from non-Laravel
        // embeddings.
        if (!function_exists('logger')) {
            return;
        }
        // @codeCoverageIgnoreEnd

        try {
            /** @var \Illuminate\Log\LogManager $logger */
            $logger  = logger();
            $channel = null;

            try {
                $channel = $logger->channel('authorization');
            } catch (\Throwable) {
                $channel = $logger;
            }

            $channel->warning(
                "Authorization: discarding corrupt resolution-cache entry '{$key}' — " . $exception->getMessage(),
                [
                    'cache_key' => $key,
                    'reason'    => $exception->getMessage(),
                ],
            );
        } catch (\Throwable) {
            // Logging failures are not allowed to abort the check.
        }
    }

    /**
     * Write a value to the configured store honouring the TTL setting and any
     * temporal-grant upper bound, routing through `tags()` on tag-capable
     * stores.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  object  $principal
     * @param  array<int, string>  $roleIds
     * @param  int|null  $maxTtl
     * @return void
     */
    private function putInStore(string $key, mixed $value, object $principal, array $roleIds, ?int $maxTtl): void
    {
        // @codeCoverageIgnoreStart
        // Defensive: every caller already checks `$this->store !== null` before
        // routing through here.
        if ($this->store === null) {
            return;
        }
        // @codeCoverageIgnoreEnd

        [$useForever, $seconds] = $this->resolveTtl($maxTtl);

        if (!$useForever && $seconds <= 0) {
            return;
        }

        $writer = $this->store;

        if ($this->isTaggable()) {
            /** @var \Illuminate\Contracts\Cache\Repository $store */
            $store = $this->store;
            // @phpstan-ignore-next-line method.notFound
            $writer = $store->tags($this->tagsFor($principal, $roleIds));
        }

        if ($useForever) {
            $writer->forever($key, $value);

            return;
        }

        $writer->put($key, $value, $seconds);
    }

    /**
     * Compute the effective TTL for a put call.
     *
     * Returns `[useForever, seconds]` — `useForever = true` short-circuits to
     * `forever()`, otherwise the seconds value is the bounded lifetime (may be
     * ≤ 0, in which case the caller skips the write).
     *
     * @param  int|null  $maxTtl
     * @return array{0: bool, 1: int}
     */
    private function resolveTtl(?int $maxTtl): array
    {
        if ($maxTtl === null) {
            return $this->ttl <= 0 ? [true, 0] : [false, $this->ttl];
        }

        $base = $this->ttl <= 0 ? \PHP_INT_MAX : $this->ttl;

        // Bound by the nearest upcoming expiry, shaving a second so the entry
        // invalidates itself before the grant actually elapses — avoids a race
        // where the cache returns a role one millisecond before the DB filter
        // would drop it.
        return [false, min($base, $maxTtl) - 1];
    }

    /**
     * Shared implementation for the role / permission cached string-list shape.
     *
     * @param  string  $kind
     * @param  object  $principal
     * @param  \Closure(): array<int, string>  $resolver
     * @param  int|null  $maxTtl
     * @param  array<int, string>  $roleIds
     * @return array<int, string>
     */
    private function rememberStringList(string $kind, object $principal, \Closure $resolver, ?int $maxTtl, array $roleIds): array
    {
        $key = $this->key($kind, $principal);

        if (array_key_exists($key, $this->memo)) {
            /** @var array<int, string> */
            return $this->memo[$key];
        }

        if ($this->store !== null) {
            try {

                /** @var mixed $raw */
                $raw = $this->readFromStore($key, $principal, $roleIds);

                if (is_array($raw)) {
                    return $this->memo[$key] = array_values(array_filter($raw, 'is_string'));
                }
            } catch (\Throwable $exception) {
                // Corrupt persistent-cache entry — forget the key, log, and
                // fall through to the fresh-read path.
                $this->forgetFromStore($key, $principal, $roleIds);
                $this->logCorruptCacheEntry($key, $exception);
            }
        }

        /** @var array<int, string> $values */
        $values           = $resolver();
        $this->memo[$key] = $values;

        if ($this->store !== null) {
            $this->putInStore($key, $values, $principal, $roleIds, $maxTtl);
        }

        return $values;
    }
}
