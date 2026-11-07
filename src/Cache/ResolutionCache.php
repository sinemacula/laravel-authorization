<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

use Illuminate\Container\Container;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Evaluation\PolicyLimits;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\AuthorizationLog;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Two-tier cache (in-memory memo plus optional persistent store) for what a
 * grantee resolves to: its roles, the keys of the roles it reaches, its
 * permissions, its policies and its permission boundaries, for what a resource
 * resolves to: the policies attached to it and to its type, and for the
 * guardrails that apply in a scope.
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

    /** @var list<string> The kinds of entry that hold policy documents, hydrated under the policy limits. */
    private const array POLICY_KINDS = ['policies', 'boundaries', 'resource-policies', 'resource-type-policies', 'guardrails'];

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
        $this->memo  = new ResolutionMemo(static fn (): string => TenantScope::scopeKey());
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
        return $this->remember('roles', $grantee, $resolve, ResolutionCodec::names(...));
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
        return $this->remember('permissions', $grantee, $resolve, ResolutionCodec::names(...));
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
        return $this->remember('policies', $grantee, $resolve, ResolutionCodec::policies(...), ResolutionCodec::encodePolicy(...));
    }

    /**
     * Return the grantee's permission boundaries that hold in the current
     * scope, resolving them on a miss. The persistent tier holds their
     * documents.
     *
     * The entry is keyed and pinned as the grantee's policies are: by the
     * grantee, the tenant and the application, holding while the grantee, the
     * version every boundary entry shares and the tenant chain are unchanged,
     * so setting or removing a boundary, or changing any policy, is seen on the
     * next check.
     *
     * @param  object  $grantee
     * @param  \Closure(\SineMacula\Laravel\Authorization\Cache\ResolutionPins): \SineMacula\Laravel\Authorization\Cache\Resolution<mixed>  $resolve
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public function rememberBoundaries(object $grantee, \Closure $resolve): array
    {
        /** @var list<\SineMacula\Laravel\Authorization\Evaluation\Policy> */
        return $this->remember('boundaries', $grantee, $resolve, ResolutionCodec::policies(...), ResolutionCodec::encodePolicy(...));
    }

    /**
     * Return the keys of the roles the grantee holds in the current scope, with
     * the keys of the roles above them when the hierarchy is enabled, resolving
     * them on a miss.
     *
     * The entry is keyed and pinned as the grantee's roles are: by the grantee,
     * the tenant and the application, holding while the grantee's grants, every
     * role it reaches and the tenant chain are unchanged, so a check that
     * matches a resource policy's role selector reads no role once it is warm.
     *
     * @param  object  $grantee
     * @param  \Closure(\SineMacula\Laravel\Authorization\Cache\ResolutionPins): \SineMacula\Laravel\Authorization\Cache\Resolution<string>  $resolve
     * @return list<string>
     */
    public function rememberRoleKeys(object $grantee, \Closure $resolve): array
    {
        /** @var list<string> */
        return $this->remember('role-keys', $grantee, $resolve, ResolutionCodec::names(...));
    }

    /**
     * Return the policies attached to the record of the type with the key, and
     * to the type, or to the type alone when there is no key, resolving them on
     * a miss. The persistent tier holds their documents, each with the resource
     * it is attached to.
     *
     * The entry is keyed by the resource, the tenant and the application, and
     * records no grantee: its resolution pins the versions the resource's type
     * and every resource policy share before it reads (see `ResolutionPins`). A
     * type alone is kept under a kind of its own, so its entry is never the
     * entry of a record, whatever the record's key.
     *
     * @param  string  $type
     * @param  string|null  $id
     * @param  \Closure(\SineMacula\Laravel\Authorization\Cache\ResolutionPins): \SineMacula\Laravel\Authorization\Cache\Resolution<mixed>  $resolve
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public function rememberResourcePolicies(string $type, ?string $id, \Closure $resolve): array
    {
        $kind = $id === null ? 'resource-type-policies' : 'resource-policies';

        /** @var list<\SineMacula\Laravel\Authorization\Evaluation\Policy> */
        return $this->remember($kind, new Reference($type, $id ?? '*'), $resolve, ResolutionCodec::policies(...), ResolutionCodec::encodePolicy(...), false);
    }

    /**
     * Return the policies attached to each record of the type with the keys,
     * and to the type, keyed by the record's key, resolving those missing
     * together on a miss: an entry for each record, as
     * `rememberResourcePolicies()` keeps it, so a check on any one of them then
     * reads its own.
     *
     * The records missing are resolved in one resolution, which pins the
     * versions their type's attachments and every resource policy share once
     * before it reads, and each entry is kept with those versions.
     *
     * @param  string  $type
     * @param  list<string>  $ids
     * @param  \Closure(\SineMacula\Laravel\Authorization\Cache\ResolutionPins, list<string>): array<array-key, \SineMacula\Laravel\Authorization\Cache\Resolution<mixed>>  $resolve
     * @return array<array-key, list<\SineMacula\Laravel\Authorization\Evaluation\Policy>>
     */
    public function rememberResourcePoliciesMany(string $type, array $ids, \Closure $resolve): array
    {
        $found   = [];
        $missing = [];

        foreach ($ids as $id) {
            $record  = new Reference($type, $id);
            $memoKey = 'resource-policies:' . PrincipalCacheKey::for($record);

            /** @var list<\SineMacula\Laravel\Authorization\Evaluation\Policy>|null $policies */
            $policies = $this->memo->get($memoKey) ?? $this->read($memoKey, $this->key('resource-policies', $record), ResolutionCodec::policies(...));

            if ($policies === null) {
                $missing[] = $id;

                continue;
            }

            $found[$id] = $policies;
        }

        if ($missing === []) {
            return $found;
        }

        $pins = new ResolutionPins($this->store);
        $held = $this->isChainHeldOncePinned($pins);

        foreach ($resolve($pins, $missing) as $id => $resolution) {
            /** @var list<\SineMacula\Laravel\Authorization\Evaluation\Policy> $policies */
            $policies   = $this->keep('resource-policies', new Reference($type, (string) $id), $resolution, $pins, $held, ResolutionCodec::encodePolicy(...));
            $found[$id] = $policies;
        }

        return $found;
    }

    /**
     * Return the guardrails that apply in the current scope, resolving them on
     * a miss. The persistent tier holds their documents.
     *
     * The entry is keyed by the tenant and the application, and records no
     * grantee: its resolution pins the version every guardrail entry shares
     * before it reads (see `ResolutionPins`), and the tenant chain is pinned as
     * for every entry, so setting or removing a guardrail, changing any policy
     * or moving the tenant in the tree is seen on the next check.
     *
     * @param  \Closure(\SineMacula\Laravel\Authorization\Cache\ResolutionPins): \SineMacula\Laravel\Authorization\Cache\Resolution<mixed>  $resolve
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public function rememberGuardrails(\Closure $resolve): array
    {
        /** @var list<\SineMacula\Laravel\Authorization\Evaluation\Policy> */
        return $this->remember('guardrails', new Reference('guardrails', '*'), $resolve, ResolutionCodec::policies(...), ResolutionCodec::encodePolicy(...), false);
    }

    /**
     * Empty the memo because the tenant the tenant scope applies has changed,
     * or, while a batch is open, set its entries aside for the scope left (see
     * `batch()`).
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
        $this->memo->scopeChanged();
    }

    /**
     * Run the callback with a batch open, within which the memo keeps the
     * entries of each scope apart rather than dropping them when the scope
     * changes, so a batch of checks moving between scopes reads what each scope
     * resolves to once. A write still drops every entry, in every scope, so a
     * later check of the batch reads it afresh. Once the outermost batch
     * closes, however the callback ends, the memo holds what it would have held
     * without one.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $callback
     * @return TResult
     */
    public function batch(\Closure $callback): mixed
    {
        $this->memo->open();

        try {
            return $callback();
        } finally {
            $this->memo->close();
        }
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
     * resolution finds when nothing it read changed as it ran. The grantee's
     * version is pinned first, unless the entry is not a grantee's.
     *
     * @param  string  $kind
     * @param  object  $grantee
     * @param  \Closure(\SineMacula\Laravel\Authorization\Cache\ResolutionPins): \SineMacula\Laravel\Authorization\Cache\Resolution<mixed>  $resolve
     * @param  \Closure(array<mixed>): list<mixed>  $decode
     * @param  (\Closure(mixed): mixed)|null  $encode
     * @param  bool  $isGrantee
     * @return list<mixed>
     */
    private function remember(string $kind, object $grantee, \Closure $resolve, \Closure $decode, ?\Closure $encode = null, bool $isGrantee = true): array
    {
        $memoKey = $kind . ':' . PrincipalCacheKey::for($grantee);

        /** @var list<mixed>|null $memoised */
        $memoised = $this->memo->get($memoKey) ?? $this->read($memoKey, $this->key($kind, $grantee), $decode);

        if ($memoised !== null) {
            return $memoised;
        }

        $pins = new ResolutionPins($this->store);

        if ($isGrantee) {
            $pins->grantee($grantee);
        }

        $held = $this->isChainHeldOncePinned($pins);

        return $this->keep($kind, $grantee, $resolve($pins), $pins, $held, $encode);
    }

    /**
     * Keep what a resolution found as the entry of the kind for the grantee, in
     * the memo, and in the store when nothing it read changed as it ran, for no
     * longer than the configured maximum, or a second before the nearest expiry
     * of a grant it counts, and return it.
     *
     * @param  string  $kind
     * @param  object  $grantee
     * @param  \SineMacula\Laravel\Authorization\Cache\Resolution<mixed>  $resolution
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionPins  $pins
     * @param  bool  $held
     * @param  (\Closure(mixed): mixed)|null  $encode
     * @return list<mixed>
     */
    private function keep(string $kind, object $grantee, Resolution $resolution, ResolutionPins $pins, bool $held, ?\Closure $encode): array
    {
        $lifetime = $resolution->expiresIn === null ? $this->ttl : \min($this->ttl, $resolution->expiresIn - 1);

        $this->memo->put($kind . ':' . PrincipalCacheKey::for($grantee), $resolution->value, $lifetime);

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

        if (!ResolutionCodec::isEntry($entry) || $this->store->tokens(\array_keys($entry['versions'])) !== $entry['versions']) {
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
     * tenant scope applies, and whether it decides just below that tenant, and
     * the subject's application.
     *
     * A policies entry, a grantee's or a resource's, is also keyed by the
     * policy limits it was hydrated under. Its documents were checked against
     * the limits when they were read from the database, and are not checked
     * again when read from the store, so a change to any limit makes every
     * entry built under the old limits miss, and the policies are read again
     * and checked against the new ones. The memo, which lasts one request or
     * job, is keyed without them, so a memo hit costs nothing more.
     *
     * @param  string  $kind
     * @param  object  $grantee
     * @return string
     */
    private function key(string $kind, object $grantee): string
    {
        return "{$this->prefix}:{$kind}:" . PrincipalCacheKey::for($grantee)
            . ':' . TenantScope::scopeKey()
            . (\in_array($kind, self::POLICY_KINDS, true) ? ':limits:' . PolicyLimits::fromConfig()->fingerprint() : '');
    }
}
