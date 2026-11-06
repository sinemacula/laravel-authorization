<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

use Illuminate\Container\Container;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\AuthorizationLog;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Two-tier cache (in-memory memo plus optional persistent store) for what a
 * grantee resolves to: its roles, its permissions and its policies.
 *
 * Persistent entries are keyed by kind, grantee and the tenant the tenant scope
 * applies, since the roles and permissions a grantee resolves to depend on it.
 * The memo is keyed by kind and grantee only, so a hit costs no lookup of the
 * tenant, and is emptied whenever the held tenant changes. Each persistent
 * entry records the version tokens of the grantee, of every role and policy it
 * was built from, and of the tenant it was built in and that tenant's
 * ancestors, and holds only while all of them are unchanged; every write bumps
 * the tokens it affects (see `Invalidation`), so a change takes effect on the
 * next check in every worker, on any store. A hit costs two reads of the store
 * and no query.
 *
 * Every entry, in either tier, lives no longer than the nearest expiry of a
 * grant it counts and never longer than the configured maximum. The memo lasts
 * one request or job (the service provider binds the cache with `scoped()`) and
 * is emptied by any write made in it. A store that fails is skipped for the
 * rest of the request or job, so checks fall back to the database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ResolutionCache
{
    use HasContainerInstance;

    /** @var \SineMacula\Laravel\Authorization\Cache\ResolutionMemo In-memory tier, keyed by full cache key. */
    private ResolutionMemo $memo;

    /** @var \SineMacula\Laravel\Authorization\Cache\VersionedStore|null Persistent tier; null keeps the memo only. */
    private ?VersionedStore $store;

    /**
     * Create a new cache instance.
     *
     * @param  \Illuminate\Contracts\Cache\Repository|null  $store
     * @param  int  $ttl
     * @param  string  $prefix
     */
    public function __construct(

        // The persistent store; null keeps the memo only.
        ?CacheRepository $store = null,

        /** The longest any entry lives, in seconds. */
        private int $ttl = 300,

        /** Namespace prefix for every key written by this cache. */
        private string $prefix = 'authorization',
    ) {
        $this->memo  = new ResolutionMemo;
        $this->store = $store === null ? null : new VersionedStore($store, $prefix);
    }

    /**
     * Return the names of the grantee's roles, resolving them on a miss.
     *
     * @param  object  $grantee
     * @param  \Closure(\SineMacula\Laravel\Authorization\Cache\ResolutionPins): \SineMacula\Laravel\Authorization\Cache\Resolution<string>  $resolve
     * @return list<string>
     */
    public function rememberRoles(object $grantee, \Closure $resolve): array
    {
        /** @var list<string> */
        return $this->remember('roles', $grantee, $resolve, static fn (array $stored): array => self::names($stored));
    }

    /**
     * Return the names of the grantee's permissions, resolving them on a miss.
     *
     * @param  object  $grantee
     * @param  \Closure(\SineMacula\Laravel\Authorization\Cache\ResolutionPins): \SineMacula\Laravel\Authorization\Cache\Resolution<string>  $resolve
     * @return list<string>
     */
    public function rememberPermissions(object $grantee, \Closure $resolve): array
    {
        /** @var list<string> */
        return $this->remember('permissions', $grantee, $resolve, static fn (array $stored): array => self::names($stored));
    }

    /**
     * Return the grantee's policies, resolving them on a miss. The persistent
     * tier holds their documents.
     *
     * @param  object  $grantee
     * @param  \Closure(\SineMacula\Laravel\Authorization\Cache\ResolutionPins): \SineMacula\Laravel\Authorization\Cache\Resolution<mixed>  $resolve
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public function rememberPolicies(object $grantee, \Closure $resolve): array
    {
        /** @var list<\SineMacula\Laravel\Authorization\Evaluation\Policy> */
        return $this->remember(
            'policies',
            $grantee,
            $resolve,
            static fn (array $stored): array => self::policies($stored),
            static fn (Policy $policy): array => ['id' => $policy->id, 'document' => $policy->toArray()],
        );
    }

    /**
     * Empty the memo because the tenant the tenant scope applies has changed.
     *
     * The memo is keyed without the tenant, so a hit costs no lookup of it: the
     * tenant is held for the request or job like the memo, and the service
     * provider and the tenant scope call this whenever the held tenant is
     * replaced or forgotten.
     *
     * @return void
     */
    public function tenantChanged(): void
    {
        $this->memo->flush();
    }

    /**
     * Empty the memo and bump the version of the tenant, which every entry
     * built in it or below it records, because the tree changed there: it moved
     * under another parent, or was deleted. Throws when the store fails, so the
     * caller can retry rather than leave stale entries. Like a grant, the
     * version is bumped again once the caller's transaction commits, a failure
     * then written to the log channel.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return void
     */
    public function treeChanged(Reference $tenant): void
    {
        $keys = $this->store === null ? [] : [$this->store->tenantKey($tenant)];

        $this->invalidate($keys);

        // Bump again once the caller's open transaction commits, on whichever
        // connection the tree lives, so an entry a concurrent check stored from
        // the tree before the commit never holds; with none open, straight
        // away.
        /** @var \Illuminate\Database\DatabaseTransactionsManager $transactions */
        $transactions = Container::getInstance()->make('db.transactions');

        $transactions->addCallback(fn () => $this->invalidateQuietly($keys));
    }

    /**
     * Return the version keys the events of a write bump, or none without a
     * persistent store.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent>  $events
     * @return list<string>
     */
    public function versionKeys(array $events): array
    {
        return $this->store === null ? [] : Invalidation::keys($this->store, $events);
    }

    /**
     * Empty the memo and bump the version keys, throwing when the store fails,
     * so a write in a transaction rolls back rather than leave stale entries.
     *
     * @param  list<string>  $keys
     * @return void
     */
    public function invalidate(array $keys): void
    {
        $this->memo->flush();
        $this->store?->bump($keys);
    }

    /**
     * Empty the memo and bump the version keys, writing a failure of the store
     * to the log channel rather than throwing it, as once a write has
     * committed.
     *
     * @param  list<string>  $keys
     * @return void
     */
    public function invalidateQuietly(array $keys): void
    {
        $this->memo->flush();
        $this->store?->bumpQuietly($keys);
    }

    /**
     * Return the entry of the kind for the grantee from the memo, then from the
     * store while its versions hold, then from the resolution, storing what the
     * resolution finds when nothing it read changed as it ran.
     *
     * @param  string  $kind
     * @param  object  $grantee
     * @param  \Closure(\SineMacula\Laravel\Authorization\Cache\ResolutionPins): \SineMacula\Laravel\Authorization\Cache\Resolution<mixed>  $resolve
     * @param  \Closure(array<mixed>): list<mixed>  $decode
     * @param  (\Closure(mixed): mixed)|null  $encode
     * @return list<mixed>
     */
    private function remember(string $kind, object $grantee, \Closure $resolve, \Closure $decode, ?\Closure $encode = null): array
    {
        $memoKey = $kind . ':' . PrincipalCacheKey::for($grantee);

        /** @var list<mixed>|null $memoised */
        $memoised = $this->memo->get($memoKey) ?? $this->read($memoKey, $this->key($kind, $grantee), $decode);

        if ($memoised !== null) {
            return $memoised;
        }

        $pins = new ResolutionPins($this->store);
        $pins->grantee($grantee);

        $held       = $this->isChainHeldOncePinned($pins);
        $resolution = $resolve($pins);
        $lifetime   = $this->lifetime($resolution->expiresIn);

        $this->memo->put($memoKey, $resolution->value, $lifetime);

        if ($resolution->stable && $held && $pins->isComplete()) {
            $this->store?->put($this->key($kind, $grantee), [
                'versions' => $pins->tokens(),
                'value'    => $encode === null ? $resolution->value : \array_map($encode, $resolution->value),
                'until'    => Carbon::now()->getTimestamp() + $lifetime,
            ], $lifetime);
        }

        return $resolution->value;
    }

    /**
     * Pin the versions of the tenant and its ancestors, then, with a store,
     * read the ancestors again, and report whether the chain held.
     *
     * The chain may have been read early in the request or job, before its
     * versions were pinned, so a tree change in between would otherwise be
     * pinned with its new version against the old ancestors. Read again after
     * the pin, a change made before it is seen and one made after it bumps a
     * pinned version. When the chain moved, the new one is pinned and read
     * from, but the entry is not stored.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionPins  $pins
     * @return bool
     */
    private function isChainHeldOncePinned(ResolutionPins $pins): bool
    {
        $chain = TenantScope::currentChain();

        $pins->tenants($chain);

        if ($this->store === null) {
            return true;
        }

        $fresh = TenantScope::refreshChain();

        if ($fresh->isSameAs($chain)) {
            return true;
        }

        $pins->tenants($fresh);

        return false;
    }

    /**
     * Return the stored entry's value, memoised for the rest of its life, or
     * null when there is none, a version it recorded has changed, or it cannot
     * be read back.
     *
     * @param  string  $memoKey
     * @param  string  $key
     * @param  \Closure(array<mixed>): list<mixed>  $decode
     * @return list<mixed>|null
     */
    private function read(string $memoKey, string $key, \Closure $decode): ?array
    {
        if ($this->store === null) {
            return null;
        }

        $entry = $this->store->get($key);

        if (!self::isEntry($entry) || $this->store->tokens(\array_keys($entry['versions'])) !== $entry['versions']) {
            return null;
        }

        try {
            $value = $decode($entry['value']);
        } catch (\Throwable $exception) {
            AuthorizationLog::warning("Authorization: discarding corrupt resolution-cache entry '{$key}' — " . $exception->getMessage(), [
                'cache_key' => $key,
                'reason'    => $exception->getMessage(),
            ]);

            $value = null;
        }

        if ($value !== null) {
            $this->memo->put($memoKey, $value, $entry['until'] - Carbon::now()->getTimestamp());
        }

        return $value;
    }

    /**
     * Return the key of the kind's entry for the grantee under the tenant the
     * tenant scope applies and the subject's application.
     *
     * @param  string  $kind
     * @param  object  $grantee
     * @return string
     */
    private function key(string $kind, object $grantee): string
    {
        $tenant      = TenantScope::currentTenant();
        $application = TenantScope::currentApplication();

        return "{$this->prefix}:{$kind}:" . PrincipalCacheKey::for($grantee)
            . ':' . ($tenant === null ? 'platform' : \implode(':', $tenant))
            . ':' . ($application === null ? 'every' : 'app:' . $application);
    }

    /**
     * Return how long an entry lives: the configured maximum, or less when a
     * grant it counts expires sooner, a second before that grant does.
     *
     * @param  int|null  $expiresIn
     * @return int
     */
    private function lifetime(?int $expiresIn): int
    {
        return $expiresIn === null ? $this->ttl : \min($this->ttl, $expiresIn - 1);
    }

    /**
     * Determine whether a stored value has the shape of an entry.
     *
     * @param  mixed  $entry
     * @return bool
     *
     * @phpstan-assert-if-true array{versions: non-empty-array<string, string>, value: array<mixed>, until: int} $entry
     */
    private static function isEntry(mixed $entry): bool
    {
        if (!\is_array($entry) || !\is_int($entry['until'] ?? null)) {
            return false;
        }

        return \is_array($entry['value'] ?? null) && \is_array($entry['versions'] ?? null) && $entry['versions'] !== [];
    }

    /**
     * Read stored names back, refusing anything that is not a list of names.
     *
     * @param  array<mixed>  $stored
     * @return list<string>
     *
     * @throws \UnexpectedValueException
     */
    private static function names(array $stored): array
    {
        foreach ($stored as $name) {
            if (!\is_string($name)) {
                throw new \UnexpectedValueException('Cached name is not a string.');
            }
        }

        /** @var list<string> */
        return $stored;
    }

    /**
     * Hydrate stored policy documents back into evaluation policies, each with
     * its stored key.
     *
     * @param  array<mixed>  $stored
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \UnexpectedValueException
     */
    private static function policies(array $stored): array
    {
        $policies = [];

        foreach ($stored as $entry) {
            $id = \is_array($entry) ? $entry['id'] ?? null : null;

            if (!\is_array($entry) || !\is_array($entry['document'] ?? null) || ($id !== null && !\is_string($id))) {
                throw new \UnexpectedValueException('Cached policy entry is not a policy document with its key.');
            }

            /** @var array<string, mixed> $document */
            $document   = $entry['document'];
            $policies[] = Policy::fromArray($document)->withId($id);
        }

        return $policies;
    }
}
