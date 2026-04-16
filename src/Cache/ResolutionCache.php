<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use SineMacula\Laravel\Authorization\Evaluation\Policy;

/**
 * Two-tier cache for principal resolution lookups.
 *
 * The hot path on every `can()` is the same repeated work: load the
 * principal's roles, roll up permissions, hydrate attached policies.
 * Within a single request Eloquent's relation cache handles the
 * identity-side queries, but across requests every `/dashboard` →
 * `/posts` handshake re-queries the same rows. This service tracks
 * both tiers:
 *
 * - **In-memory memo** — always on, keyed per principal. Zero
 *   configuration, avoids re-computing `getPermissions()` and
 *   re-hydrating `Policy` documents within a request even when a
 *   caller skips the relation cache (`$user->fresh()->getPermissions()`).
 * - **Persistent store** — optional. Enabled when
 *   `authorization.cache.store` points at a configured cache
 *   connection. Lookups fall back to the store on memo miss;
 *   resolver results are written to the store on populate. TTL
 *   comes from `authorization.cache.ttl` (0 = forever).
 *
 * Invalidation is event-driven — the `InvalidateResolutionCache`
 * listener calls `forget()` on principal-scoped events and
 * `flush()` on role-pivot mutations (no reverse index into which
 * identities hold a role). Policies are serialised through
 * `Policy::toArray()` / `fromArray()` to stay forward-compatible
 * with policy-document schema bumps.
 *
 * **Temporal-grant caveat:** `expires_at` on the `authorizable_*`
 * pivots is filtered at the database layer on every relation
 * read, but the cache has no way to observe wall-clock advance.
 * A memoised role / permission list reflects the state at
 * population time — if an entry expires after the cache was
 * populated, the stale entry is still returned until an
 * invalidation event fires (assign / revoke / attach / detach
 * on the same identity, or a role-pivot mutation). Deployments
 * that lean heavily on temporal grants should either disable
 * the persistent tier or pair it with a short TTL.
 * Tracked as ISSUES.md #77.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ResolutionCache
{
    /** In-memory per-principal memo, keyed by full cache key. */
    private array $memo = [];

    /**
     * Create a new cache instance.
     *
     * @param  \Illuminate\Contracts\Cache\Repository|null  $store
     * @param  int  $ttl
     * @param  string  $prefix
     */
    public function __construct(

        /** Optional persistent cache store; null disables cross-request caching. */
        private readonly ?CacheRepository $store = null,

        /** Entry lifetime in seconds; 0 stores forever. */
        private readonly int $ttl = 0,

        /** Namespace prefix for every key written by this cache. */
        private readonly string $prefix = 'authorization',

    ) {}

    /**
     * Return the cached list of policies for the principal, or
     * invoke the resolver and cache its output.
     *
     * @param  object  $principal
     * @param  \Closure(): array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $resolver
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public function rememberPolicies(object $principal, \Closure $resolver): array
    {
        $key = $this->key('policies', $principal);

        if (\array_key_exists($key, $this->memo)) {
            /** @var array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy> $cached */
            $cached = $this->memo[$key];

            return $cached;
        }

        if ($this->store !== null) {
            try {
                /** @var mixed $raw */
                $raw = $this->store->get($key);

                if (\is_array($raw)) {
                    $policies = [];

                    foreach ($raw as $document) {
                        if (!\is_array($document)) {
                            throw new \UnexpectedValueException('Cached policy entry is not an array document.');
                        }

                        // @var array<string, mixed> $document
                        $policies[] = Policy::fromArray($document);
                    }

                    return $this->memo[$key] = $policies;
                }
            } catch (\Throwable $exception) {
                // Corrupt persistent-cache entry — forget the key,
                // log through the `authorization` channel, and fall
                // through to the fresh-read path below. Matches the
                // fail-closed + self-healing pattern used in
                // `HasPolicies::logMalformedPolicy()`.
                $this->store->forget($key);
                $this->logCorruptCacheEntry($key, $exception);
            }
        }

        /** @var array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy> $policies */
        $policies         = $resolver();
        $this->memo[$key] = $policies;

        if ($this->store !== null) {
            $documents = \array_map(static fn (Policy $policy): array => $policy->toArray(), $policies);
            $this->putInStore($key, $documents);
        }

        return $policies;
    }

    /**
     * Return the cached permission-name list for the principal, or
     * invoke the resolver and cache its output.
     *
     * @param  object  $principal
     * @param  \Closure(): array<int, string>  $resolver
     * @return array<int, string>
     */
    public function rememberPermissions(object $principal, \Closure $resolver): array
    {
        return $this->rememberStringList('permissions', $principal, $resolver);
    }

    /**
     * Return the cached role-name list for the principal, or
     * invoke the resolver and cache its output.
     *
     * @param  object  $principal
     * @param  \Closure(): array<int, string>  $resolver
     * @return array<int, string>
     */
    public function rememberRoles(object $principal, \Closure $resolver): array
    {
        return $this->rememberStringList('roles', $principal, $resolver);
    }

    /**
     * Drop every cached entry for the supplied principal — memo
     * and persistent store alike. Listeners call this on
     * principal-scoped mutations (`IdentityRoleAssigned`,
     * `IdentityPermissionGranted`, `IdentityPolicyAttached`, and
     * their inverses).
     *
     * @param  object  $principal
     * @return void
     */
    public function forget(object $principal): void
    {
        foreach (['policies', 'permissions', 'roles'] as $kind) {
            $key = $this->key($kind, $principal);
            unset($this->memo[$key]);
            $this->store?->forget($key);
        }
    }

    /**
     * Drop every in-memory entry. Listeners call this on role
     * pivot changes (`RolePermissionGranted` /
     * `RolePermissionRevoked`) because the cache holds no reverse
     * index from role to the identities carrying it — a granular
     * per-principal invalidation would require a pivot walk that
     * defeats the cache's purpose.
     *
     * @return void
     */
    public function flush(): void
    {
        $this->memo = [];
        // Persistent store is not cleared here because flushing the
        // entire configured cache would wipe unrelated entries —
        // the per-request memo reset is the practical safety net,
        // and consumers running hot role-pivot mutations should
        // use a cache tag in a future extension.
    }

    /**
     * Shared implementation for the role / permission cached
     * string-list shape.
     *
     * @param  string  $kind
     * @param  object  $principal
     * @param  \Closure(): array<int, string>  $resolver
     * @return array<int, string>
     */
    private function rememberStringList(string $kind, object $principal, \Closure $resolver): array
    {
        $key = $this->key($kind, $principal);

        if (\array_key_exists($key, $this->memo)) {
            /** @var array<int, string> $cached */
            return $this->memo[$key];
        }

        if ($this->store !== null) {
            try {
                /** @var mixed $raw */
                $raw = $this->store->get($key);

                if (\is_array($raw)) {
                    return $this->memo[$key] = \array_values(\array_filter($raw, 'is_string'));
                }
            } catch (\Throwable $exception) {
                // Corrupt persistent-cache entry — forget the key,
                // log, and fall through to the fresh-read path.
                $this->store->forget($key);
                $this->logCorruptCacheEntry($key, $exception);
            }
        }

        /** @var array<int, string> $values */
        $values           = $resolver();
        $this->memo[$key] = $values;

        if ($this->store !== null) {
            $this->putInStore($key, $values);
        }

        return $values;
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
     * Eloquent models already expose the canonical pairing
     * (`getMorphClass()` + `getKey()`) and that remains the first
     * choice. Non-Eloquent principals — a service-account value
     * object, a tenant-scoped identity shell, any class implementing
     * `AuthorizableIdentity` without extending `Model` — are
     * duck-typed: if they expose compatible `getMorphClass()` /
     * `getKey()` accessors the persistent tier keys on those and
     * survives across requests. Principals that expose neither fall
     * back to the concrete class name plus `spl_object_hash()`,
     * which is only stable within a single request. The in-memory
     * memo still benefits; the persistent tier is effectively
     * per-request for those principals (see ISSUES.md #70 option
     * (a) — the duck-typed path lets well-behaved custom
     * principals opt in to cross-request caching without a new
     * contract).
     *
     * @param  object  $principal
     * @return string
     */
    private function keyFor(object $principal): string
    {
        $type = $principal::class;
        $id   = null;

        if (\method_exists($principal, 'getMorphClass')) {
            /** @var mixed $morph */
            $morph = $principal->getMorphClass();

            if (\is_string($morph) && $morph !== '') {
                $type = $morph;
            }
        }

        if (\method_exists($principal, 'getKey')) {
            /** @var mixed $raw */
            $raw = $principal->getKey();

            if (\is_string($raw) || \is_int($raw)) {
                $candidate = (string) $raw;

                if ($candidate !== '') {
                    $id = $candidate;
                }
            }
        }

        if ($id === null) {
            $id = 'obj:' . \spl_object_hash($principal);
        }

        return "{$type}:{$id}";
    }

    /**
     * Report a corrupt persistent-cache entry without raising — the
     * caller has already forgotten the key and will recompute via
     * the resolver, so the cache self-heals on the same request.
     *
     * @param  string  $key
     * @param  \Throwable  $exception
     * @return void
     */
    private function logCorruptCacheEntry(string $key, \Throwable $exception): void
    {
        if (!\function_exists('logger')) {
            return;
        }

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
     * Write a value to the configured store honouring the TTL
     * setting — `0` is persisted forever, everything else has a
     * second-based lifetime.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return void
     */
    private function putInStore(string $key, mixed $value): void
    {
        if ($this->store === null) {
            return;
        }

        if ($this->ttl <= 0) {
            $this->store->forever($key, $value);

            return;
        }

        $this->store->put($key, $value, $this->ttl);
    }
}
