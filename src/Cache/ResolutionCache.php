<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

use Illuminate\Container\Container;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Database\BreakGlassActivations;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\AuthorizationLog;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Usage\RouteMap;

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

    /** @var string The prefix of the memo key the routes behind an entry are kept under. */
    private const string ROUTES = 'routes:';

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
     * @param  bool  $isTrackingUsage
     */
    public function __construct(

        // The persistent store; null keeps the memo only.
        ?CacheRepository $store = null,

        /** The longest any entry lives, in seconds. */
        private int $ttl = 300,

        /** Namespace prefix for every key written by this cache. */
        private string $prefix = 'authorization',

        /** Whether grant usage is tracked, so a grantee's permissions and policies are kept with the routes of the grants behind them. */
        private bool $isTrackingUsage = false,
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
        return $this->remember(
            'policies',
            $grantee,
            static fn (ResolutionPins $pins): Resolution => ResolutionCodec::policyResolution($resolve($pins)),
            ResolutionCodec::policies(...),
            ResolutionCodec::encodePolicy(...),
        );
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
        return $this->remember(
            'boundaries',
            $grantee,
            static fn (ResolutionPins $pins): Resolution => ResolutionCodec::policyResolution($resolve($pins)),
            ResolutionCodec::policies(...),
            ResolutionCodec::encodePolicy(...),
        );
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
        return $this->remember(
            $kind,
            new Reference($type, $id ?? '*'),
            static fn (ResolutionPins $pins): Resolution => ResolutionCodec::policyResolution($resolve($pins)),
            ResolutionCodec::policies(...),
            ResolutionCodec::encodePolicy(...),
            false,
        );
    }

    /**
     * Return the policies attached to each record of the type with the keys,
     * and to the type, keyed by the record's key, resolving those missing
     * together on a miss: an entry for each record, as
     * `rememberResourcePolicies()` keeps it, so a check on any one of them then
     * reads its own.
     *
     * The records the memo does not hold are read from the store together, in
     * one read of their entries and one of the versions those entries recorded,
     * and those missing are resolved in one resolution, which pins the versions
     * their type's attachments and every resource policy share once before it
     * reads; each entry is kept with those versions, and written to the store
     * with the others in one write, so the store costs the same however many
     * records there are.
     *
     * @param  string  $type
     * @param  list<string>  $ids
     * @param  \Closure(\SineMacula\Laravel\Authorization\Cache\ResolutionPins, list<string>): array<array-key, \SineMacula\Laravel\Authorization\Cache\Resolution<mixed>>  $resolve
     * @return array<array-key, list<\SineMacula\Laravel\Authorization\Evaluation\Policy>>
     */
    public function rememberResourcePoliciesMany(string $type, array $ids, \Closure $resolve): array
    {
        $found  = [];
        $stored = [];

        foreach ($ids as $id) {
            $record  = new Reference($type, $id);
            $memoKey = 'resource-policies:' . PrincipalCacheKey::for($record);

            /** @var list<\SineMacula\Laravel\Authorization\Evaluation\Policy>|null $policies */
            $policies = $this->memo->get($memoKey);

            if ($policies !== null) {
                $found[$id] = $policies;

                continue;
            }

            $stored[] = [$id, $memoKey, PrincipalCacheKey::entry($this->prefix, 'resource-policies', $record)];
        }

        $entries = $this->store?->entries(\array_column($stored, 2)) ?? [];
        $missing = [];

        foreach ($stored as [$id, $memoKey, $key]) {
            /** @var list<\SineMacula\Laravel\Authorization\Evaluation\Policy>|null $policies */
            $policies = $this->read($memoKey, $key, ResolutionCodec::policies(...), $entries);

            if ($policies === null) {
                $missing[] = $id;

                continue;
            }

            $found[$id] = $policies;
        }

        if ($missing === []) {
            return $found;
        }

        $pins   = new ResolutionPins($this->store);
        $held   = $pins->isChainHeldOncePinned();
        $writes = [];

        foreach ($resolve($pins, $missing) as $id => $resolution) {
            $resolved   = ResolutionCodec::policyResolution($resolution);
            $found[$id] = $this->keep('resource-policies', new Reference($type, (string) $id), $resolved, $pins, $held, ResolutionCodec::encodePolicy(...), $writes);
        }

        $this->store?->putMany($writes);

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
        return $this->remember(
            'guardrails',
            new Reference('guardrails', '*'),
            static fn (ResolutionPins $pins): Resolution => ResolutionCodec::policyResolution($resolve($pins)),
            ResolutionCodec::policies(...),
            ResolutionCodec::encodePolicy(...),
            false,
        );
    }

    /**
     * Return the routes of the stored grants behind each of the grantee's
     * permissions, by its name, or each of its policies, by its key, as the
     * entry of the kind its resolution kept holds them while grant usage is
     * tracked (see `Usage\RouteSources`); null when the memo holds none, as
     * when usage is not tracked, the grantee's grants were not resolved in the
     * current scope, or its resolution could not say.
     *
     * The routes are kept beside the entry, in the memo and the store alike,
     * for as long as it lives, so a check finds those behind its decision with
     * no query once the entry is warm.
     *
     * @param  string  $kind
     * @param  object  $grantee
     * @return \SineMacula\Laravel\Authorization\Usage\RouteMap|null
     *
     * @phpstan-impure
     */
    public function routesOf(string $kind, object $grantee): ?RouteMap
    {
        $kind   = BreakGlassActivations::kindFor(ResolutionCodec::kindOf($kind, $this->isTrackingUsage), $grantee);
        $routes = $this->memo->get(self::ROUTES . $kind . ':' . PrincipalCacheKey::for($grantee))[0] ?? null;

        return $routes instanceof RouteMap ? $routes : null;
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
     * Given `$isForgettingDecisions`, the tenant was forgotten with everything
     * else the request or job remembers towards its decisions (N112, see
     * `Evaluation\DecisionMemory`): every entry is dropped, in every scope, and
     * so are those set aside for a scope left or for a callback run in another
     * (see `batch()`), which are never put back, and the tenant tree's answers,
     * so what the request or job resolved is read afresh, from the store while
     * its versions hold, else from the database. The store is not touched and
     * no version key is bumped: nothing was written, so what other workers hold
     * stays valid.
     *
     * @param  bool  $isForgettingDecisions
     * @return void
     */
    public function tenantChanged(bool $isForgettingDecisions = false): void
    {
        if ($isForgettingDecisions) {
            $this->memo->flush();
        }

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
     * Given `$isAside`, the callback runs in another scope and returns to the
     * one it is called in, so the entries the memo holds as the batch opens are
     * put back once it closes, unless a write dropped them meanwhile (see
     * `ResolutionMemo::aside()`): `AuthorizationScope` runs `permissionsFor()`
     * this way, so listing in another scope keeps what the request resolved.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $callback
     * @param  bool  $isAside
     * @return TResult
     */
    public function batch(\Closure $callback, bool $isAside = false): mixed
    {
        $run = function () use ($callback): mixed {
            $this->memo->open();

            try {
                return $callback();
            } finally {
                $this->memo->close();
            }
        };

        return $isAside ? $this->memo->aside($run) : $run();
    }

    /**
     * Return the tenant tree's answer to the question, asked once while a batch
     * is open, so a batch of checks over many resources of a few tenants reads
     * each tenant's place in the tree once (see `ResolutionMemo::tree()`): the
     * answer already given, or the one the callback reads, or, asked afresh,
     * the one it reads in place of the one kept. A write, a change to the tree
     * reported among them, drops every answer, so a later check of the batch
     * asks the tree again.
     *
     * @template TAnswer
     *
     * @param  list<string>  $question
     * @param  \Closure(): TAnswer  $answer
     * @param  bool  $isFresh
     * @return TAnswer
     */
    public function answerTree(array $question, \Closure $answer, bool $isFresh = false): mixed
    {
        return $this->memo->tree($question, $answer, $isFresh);
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
     * Return the version keys the events of a write bump, with those of the
     * grantees given whose grants a write changed without an event, as one
     * written to a break-glass activation, or none without a persistent store.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent>  $events
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Support\Reference>  $grantees
     * @return list<string>
     */
    public function versionKeys(array $events, array $grantees = []): array
    {
        return $this->store === null ? [] : Invalidation::keys($this->store, $events, $grantees);
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
     * @template TValue
     *
     * @param  string  $kind
     * @param  object  $grantee
     * @param  \Closure(\SineMacula\Laravel\Authorization\Cache\ResolutionPins): \SineMacula\Laravel\Authorization\Cache\Resolution<TValue>  $resolve
     * @param  \Closure(array<mixed>): list<mixed>  $decode
     * @param  (\Closure(TValue): mixed)|null  $encode
     * @param  bool  $isGrantee
     * @return list<mixed>
     */
    private function remember(string $kind, object $grantee, \Closure $resolve, \Closure $decode, ?\Closure $encode = null, bool $isGrantee = true): array
    {
        // Every check reads through here, so the kind is renamed for routed
        // entries only while usage is tracked, at no cost when it is not.
        if ($this->isTrackingUsage) {
            $kind = ResolutionCodec::kindOf($kind, true);
        }

        // An instance read as another subject's identity counts none of its
        // break-glass activations, so its entries are kept apart.
        $kind    = BreakGlassActivations::kindFor($kind, $grantee);
        $memoKey = $kind . ':' . PrincipalCacheKey::for($grantee);

        /** @var list<mixed>|null $memoised */
        $memoised = $this->memo->get($memoKey) ?? $this->read($memoKey, PrincipalCacheKey::entry($this->prefix, $kind, $grantee), $decode);

        if ($memoised !== null) {
            return $memoised;
        }

        $pins = new ResolutionPins($this->store, ResolutionCodec::isRouted($kind));

        if ($isGrantee) {
            $pins->grantee($grantee);
        }

        $held = $pins->isChainHeldOncePinned();

        return $this->keep($kind, $grantee, $resolve($pins), $pins, $held, $encode);
    }

    /**
     * Keep what a resolution found as the entry of the kind for the grantee, in
     * the memo, and in the store when nothing it read changed as it ran, for no
     * longer than the configured maximum, or a second before the nearest expiry
     * of a grant it counts, and return it. Given the writes of a bulk read, the
     * entry is added to them, under its lifetime, to be written with the rest
     * at once, rather than written now.
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
    private function keep(string $kind, object $grantee, Resolution $resolution, ResolutionPins $pins, bool $held, ?\Closure $encode, ?array &$writes = null): array
    {
        $lifetime = $resolution->expiresIn === null ? $this->ttl : \min($this->ttl, $resolution->expiresIn - 1);
        $memoKey  = $kind . ':' . PrincipalCacheKey::for($grantee);

        $this->memo->put($memoKey, $resolution->value, $lifetime);

        if ($resolution->routes !== null) {
            $this->memo->put(self::ROUTES . $memoKey, [$resolution->routes], $lifetime);
        }

        if ($this->store === null || !$resolution->stable || !$held || !$pins->isComplete()) {
            return $resolution->value;
        }

        $key   = PrincipalCacheKey::entry($this->prefix, $kind, $grantee);
        $entry = [
            'versions' => $pins->tokens(),
            'value'    => $encode === null ? $resolution->value : \array_map($encode, $resolution->value),
            'until'    => Carbon::now()->getTimestamp() + $lifetime,
            ...ResolutionCodec::encodeRoutes($resolution->routes),
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
     * null when there is none, a version it recorded has changed, or it cannot
     * be read back. Given the entries a bulk read found, whose versions it has
     * checked, the entry is taken from those, without reading the store again.
     *
     * @param  string  $memoKey
     * @param  string  $key
     * @param  \Closure(array<mixed>): list<mixed>  $decode
     * @param  array<string, array{versions: array<string, string>, value: array<mixed>, until: int}>|null  $entries
     * @return list<mixed>|null
     */
    private function read(string $memoKey, string $key, \Closure $decode, ?array $entries = null): ?array
    {
        if ($this->store === null) {
            return null;
        }

        $entry = $entries === null ? $this->store->get($key) : $entries[$key] ?? null;

        if (!ResolutionCodec::isEntry($entry) || ($entries === null && $this->store->tokens(\array_keys($entry['versions'])) !== $entry['versions'])) {
            return null;
        }

        try {
            $value  = $decode($entry['value']);
            $routes = \array_key_exists('routes', $entry) ? ResolutionCodec::routes($entry['routes']) : null;
        } catch (\Throwable $exception) {
            AuthorizationLog::warning("Authorization: discarding corrupt resolution-cache entry '{$key}' — " . $exception->getMessage(), [
                'cache_key' => $key,
                'reason'    => $exception->getMessage(),
            ]);

            $value  = null;
            $routes = null;
        }

        if ($value !== null) {
            $this->memo->put($memoKey, $value, $entry['until'] - Carbon::now()->getTimestamp());
        }

        if ($value !== null && $routes !== null) {
            $this->memo->put(self::ROUTES . $memoKey, [$routes], $entry['until'] - Carbon::now()->getTimestamp());
        }

        return $value;
    }
}
