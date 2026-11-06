<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\PrincipalCacheKey;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\FailingCacheStore;
use Tests\Feature\Stubs\NonTaggableCacheStore;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for the two-tier resolution cache: the memo, the persistent
 * entries and the versions that decide whether an entry still holds, entry
 * lifetimes, the tenant in the key, and a store that fails.
 *
 * Each "request" is a fresh cache instance over the same store, as the service
 * provider's scoped binding gives every request or job.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResolutionCache::class)]
#[CoversClass(PrincipalCacheKey::class)]
final class ResolutionCacheTest extends TestCase
{
    use ActsAsTenant;

    /** @var \Illuminate\Cache\Repository The store every request of a test shares. */
    private Repository $store;

    /** @var int How many times a resolution ran. */
    private int $resolutions = 0;

    /**
     * Start the clock and give every request of the test one store.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-07-01 12:00:00');

        $this->store = new Repository(new ArrayStore);
    }

    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * A second read in the same request is served from the memo, and one in the
     * next request from the store, without resolving again.
     *
     * @return void
     */
    public function testEntriesAreServedFromTheMemoThenTheStore(): void
    {
        $cache = $this->request();

        self::assertSame(['posts:read'], $this->permissions($cache));
        self::assertSame(['posts:read'], $this->permissions($cache));
        self::assertSame(['posts:read'], $this->permissions($this->request()));
        self::assertSame(1, $this->resolutions);
    }

    /**
     * Without a store only the memo holds entries, so the next request resolves
     * again.
     *
     * @return void
     */
    public function testWithoutAStoreOnlyTheMemoHolds(): void
    {
        $cache = new ResolutionCache;

        $this->permissions($cache);
        $this->permissions($cache);
        $this->permissions(new ResolutionCache);

        self::assertSame(2, $this->resolutions);
        self::assertSame([], $cache->versionKeys([new RoleAssigned(Operation::begin(), self::grantee(), new Reference('role', 'role-1'), 'editor', GrantScope::platform(), null)]));
    }

    /**
     * An entry built in a tenant records the versions of the tenant and its
     * ancestors, so a change to the tree at any of them drops it, in the memo
     * and the store; a change elsewhere leaves it.
     *
     * @return void
     */
    public function testATreeChangeAtOrAboveTheTenantDropsItsEntries(): void
    {
        [$account, $org] = \array_map(self::createTenant(...), ['account', 'org']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($account), Reference::of($org)));
        $this->actAsTenant($account);

        $cache = $this->request();

        $this->permissions($cache);
        $this->permissions($this->request());
        $this->request()->treeChanged(new Reference('stub_tenant', 'elsewhere'));
        $this->permissions($this->request());

        self::assertSame(1, $this->resolutions);

        $cache->treeChanged(Reference::of($org));

        $this->permissions($cache);
        $this->permissions($this->request());

        self::assertSame(2, $this->resolutions);

        $this->request()->treeChanged(Reference::of($account));
        $this->permissions($this->request());

        self::assertSame(3, $this->resolutions);
    }

    /**
     * Without a store a tree change empties the memo only.
     *
     * @return void
     */
    public function testWithoutAStoreATreeChangeEmptiesTheMemo(): void
    {
        $cache = new ResolutionCache;

        $this->permissions($cache);
        $cache->treeChanged(new Reference('stub_tenant', 'org'));
        $this->permissions($cache);

        self::assertSame(2, $this->resolutions);
    }

    /**
     * An entry lives no longer than the configured maximum, in either tier.
     *
     * @return void
     */
    public function testEntriesLiveNoLongerThanTheMaximum(): void
    {
        $cache = $this->request(ttl: 60);

        $this->permissions($cache);

        Carbon::setTestNow('2026-07-01 12:00:59');

        $this->permissions($cache);
        $this->permissions($this->request(ttl: 60));

        self::assertSame(1, $this->resolutions);

        Carbon::setTestNow('2026-07-01 12:01:00');

        // The new request resolves again; the first request's memo has lapsed
        // too and reads the entry the new request stored.
        $this->permissions($this->request(ttl: 60));
        $this->permissions($cache);

        self::assertSame(2, $this->resolutions);
    }

    /**
     * A grant that expires sooner than the maximum ends the entry a second
     * before it does.
     *
     * @return void
     */
    public function testAnExpiringGrantEndsTheEntryASecondBefore(): void
    {
        $cache = $this->request();

        $this->permissions($cache, expiresIn: 30);

        Carbon::setTestNow('2026-07-01 12:00:28');

        $this->permissions($this->request(), expiresIn: 2);

        self::assertSame(1, $this->resolutions);

        Carbon::setTestNow('2026-07-01 12:00:29');

        $this->permissions($this->request(), expiresIn: 1);
        $this->permissions($cache, expiresIn: 1);

        self::assertSame(3, $this->resolutions);
    }

    /**
     * A grant expiring within the second is resolved but never stored.
     *
     * @return void
     */
    public function testAnEntryThatHasAlreadyLapsedIsNotStored(): void
    {
        $cache = $this->request();

        $this->permissions($cache, expiresIn: 1);
        $this->permissions($cache, expiresIn: 1);
        $this->permissions($this->request(), expiresIn: 1);

        self::assertSame(3, $this->resolutions);
    }

    /**
     * A resolution that saw its records change as it ran is returned but not
     * stored.
     *
     * @return void
     */
    public function testAnUnstableResolutionIsNotStored(): void
    {
        $this->permissions($this->request(), stable: false);
        $this->permissions($this->request());

        self::assertSame(2, $this->resolutions);
    }

    /**
     * Bumping the grantee's version invalidates its entries in every request,
     * and empties the memo of the one that bumped it.
     *
     * @return void
     */
    public function testBumpingTheGranteeInvalidatesItsEntries(): void
    {
        $cache = $this->request();

        $this->permissions($cache);
        $cache->invalidate([$this->versions()->granteeKey(self::grantee())]);
        $this->permissions($cache);

        self::assertSame(2, $this->resolutions);

        $this->request()->invalidateQuietly([$this->versions()->granteeKey(self::grantee())]);
        $this->permissions($this->request());

        self::assertSame(3, $this->resolutions);
    }

    /**
     * An entry holds while the versions of the roles it pinned are unchanged:
     * bumping an unrelated role leaves it, bumping one it pinned ends it.
     *
     * @return void
     */
    public function testAnEntryFollowsTheRolesItPinned(): void
    {
        $this->permissions($this->request(), roles: ['role-1']);

        $this->request()->invalidate([$this->versions()->roleKey('role-2')]);
        $this->permissions($this->request(), roles: ['role-1']);

        self::assertSame(1, $this->resolutions);

        $this->request()->invalidate([$this->versions()->roleKey('role-1')]);
        $this->permissions($this->request(), roles: ['role-1']);

        self::assertSame(2, $this->resolutions);
    }

    /**
     * An entry is stored under the tenant the tenant scope applies, and the
     * memo is emptied when the tenant changes.
     *
     * @return void
     */
    public function testEntriesAreKeptPerTenant(): void
    {
        $first  = self::createTenant('t-1');
        $second = self::createTenant('t-2');

        $this->actAsTenant($first);
        $cache = $this->request();
        $this->permissions($cache);

        $this->actAsTenant($second);
        $this->permissions($cache);

        self::assertSame(2, $this->resolutions);

        $this->actAsTenant($first);
        $this->permissions($cache);
        $this->permissions($this->request());

        self::assertSame(2, $this->resolutions);

        TenantScope::currentTenant();
        (new TenantScope)->flushResolvedTenant();
        $this->permissions($this->app?->make(ResolutionCache::class) ?? $cache);

        self::assertSame(2, $this->resolutions);
    }

    /**
     * Policies are stored as their documents and hydrated back.
     *
     * @return void
     */
    public function testPoliciesAreStoredAsDocuments(): void
    {
        $policy = EvaluationPolicy::fromArray(['version' => 1, 'name' => 'readers', 'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]);

        $this->request()->rememberPolicies(self::grantee(), fn (): Resolution => $this->resolve([$policy]));

        $read = $this->request()->rememberPolicies(self::grantee(), fn (): Resolution => $this->resolve([]));

        self::assertSame(1, $this->resolutions);
        self::assertEquals([$policy], $read);
    }

    /**
     * Roles are stored under their own kind, apart from permissions.
     *
     * @return void
     */
    public function testRolesAreKeptApartFromPermissions(): void
    {
        $cache = $this->request();

        $roles = $cache->rememberRoles(self::grantee(), fn (): Resolution => $this->resolve(['editor']));

        self::assertSame(['editor'], $roles);
        self::assertSame(['posts:read'], $this->permissions($cache));
        self::assertSame(['editor'], $this->request()->rememberRoles(self::grantee(), fn (): Resolution => $this->resolve([])));
        self::assertSame(2, $this->resolutions);
    }

    /**
     * An entry that cannot be read back is written to the log channel and
     * resolved again; a value that is not an entry is resolved again quietly.
     *
     * @return void
     */
    public function testAnUnreadableEntryIsResolvedAgain(): void
    {
        $logger = $this->recordLogs();
        $cache  = $this->request();

        $this->permissions($cache);

        $key   = 'authorization-test:permissions:' . PrincipalCacheKey::for(self::grantee()) . ':platform';
        $entry = $this->store->get($key);
        self::assertIsArray($entry);

        $this->store->put($key, [...$entry, 'value' => [42]], 60);
        $this->permissions($this->request());

        self::assertSame(2, $this->resolutions);
        self::assertSame(["Authorization: discarding corrupt resolution-cache entry '{$key}' — Cached name is not a string."], $logger->messages());

        $this->store->put($key, 'not an entry', 60);
        $this->permissions($this->request());

        self::assertSame(3, $this->resolutions);
        self::assertCount(1, $logger->records);
    }

    /**
     * A stored value without the whole shape of an entry is resolved again,
     * without a warning.
     *
     * @return void
     */
    public function testAValueWithoutTheShapeOfAnEntryIsResolvedAgain(): void
    {
        $logger = $this->recordLogs();

        $this->permissions($this->request());

        $key   = 'authorization-test:permissions:' . PrincipalCacheKey::for(self::grantee()) . ':platform';
        $entry = $this->store->get($key);
        self::assertIsArray($entry);

        foreach ([['until' => 'soon'], ['value' => 'posts:read'], ['versions' => []], ['versions' => 'v1']] as $damage) {
            $this->store->put($key, [...$entry, ...$damage], 60);
            $this->permissions($this->request());
        }

        self::assertSame(5, $this->resolutions);
        self::assertSame([], $logger->records);
    }

    /**
     * An entry read from the store is memoised for the rest of its life, so the
     * request reads the store once.
     *
     * @return void
     */
    public function testAStoreHitIsMemoisedForTheRestOfItsLife(): void
    {
        $this->permissions($this->request());

        $cache = $this->request();

        self::assertSame(['posts:read'], $this->permissions($cache));

        $key   = 'authorization-test:permissions:' . PrincipalCacheKey::for(self::grantee()) . ':platform';
        $entry = $this->store->get($key);
        self::assertIsArray($entry);

        $this->store->put($key, [...$entry, 'value' => ['posts:write']], 60);

        self::assertSame(['posts:read'], $this->permissions($cache));

        Carbon::setTestNow('2026-07-01 12:05:00');

        self::assertSame(['posts:read'], $this->permissions($cache));
        self::assertSame(2, $this->resolutions);
    }

    /**
     * Stored policy documents that cannot be hydrated are resolved again.
     *
     * @return void
     */
    public function testAnUnreadablePolicyDocumentIsResolvedAgain(): void
    {
        $this->recordLogs();
        $this->request()->rememberPolicies(self::grantee(), fn (): Resolution => $this->resolve([]));

        $key   = 'authorization-test:policies:' . PrincipalCacheKey::for(self::grantee()) . ':platform';
        $entry = $this->store->get($key);
        self::assertIsArray($entry);

        $this->store->put($key, [...$entry, 'value' => ['not a document']], 60);

        self::assertSame([], $this->request()->rememberPolicies(self::grantee(), fn (): Resolution => $this->resolve([])));
        self::assertSame(2, $this->resolutions);
    }

    /**
     * Any store works, with or without tags.
     *
     * @return void
     */
    public function testAStoreWithoutTagsWorks(): void
    {
        $this->store = new Repository(new NonTaggableCacheStore);

        $this->permissions($this->request());
        $this->permissions($this->request());

        self::assertSame(1, $this->resolutions);
    }

    /**
     * A store that fails never fails a check: the resolution runs, the failure
     * is written to the log channel once, and the store is not asked again in
     * the request.
     *
     * @return void
     */
    public function testAFailingStoreFallsBackToTheResolution(): void
    {
        $logger = $this->recordLogs();
        $driver = new FailingCacheStore;

        $this->store = new Repository($driver);
        $cache       = $this->request();

        self::assertSame(['posts:read'], $this->permissions($cache));

        $calls = $driver->calls;

        $cache->invalidateQuietly([]);
        self::assertSame(['posts:read'], $this->permissions($cache));
        self::assertSame($calls, $driver->calls);
        self::assertSame(2, $this->resolutions);
        self::assertSame(
            ['Authorization: the resolution cache store failed, so checks read the database for the rest of this request or job — cache unavailable'],
            $logger->messages(),
        );
    }

    /**
     * Invalidating in a write's transaction throws when the store fails, so the
     * write rolls back; invalidating once it has committed only writes the
     * failure to the log channel.
     *
     * @return void
     */
    public function testInvalidationFailuresAreThrownOnlyBeforeCommit(): void
    {
        $logger      = $this->recordLogs();
        $this->store = new Repository(new FailingCacheStore);
        $keys        = [$this->versions()->granteeKey(self::grantee())];

        $this->request()->invalidateQuietly($keys);

        self::assertCount(1, $logger->records);

        $this->expectExceptionObject(new \RuntimeException('cache unavailable'));

        $this->request()->invalidate($keys);
    }

    /**
     * Without a store, invalidating empties the memo and bumps nothing.
     *
     * @return void
     */
    public function testWithoutAStoreInvalidatingEmptiesTheMemo(): void
    {
        $cache = new ResolutionCache;

        $this->permissions($cache);
        $cache->invalidate(['anything']);
        $this->permissions($cache);
        $cache->tenantChanged();
        $this->permissions($cache);

        self::assertSame(3, $this->resolutions);
    }

    /**
     * Resolve the grantee's permissions through the cache, pinning the given
     * roles as a resolution does.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCache  $cache
     * @param  int|null  $expiresIn
     * @param  bool  $stable
     * @param  list<string>  $roles
     * @return list<string>
     */
    private function permissions(ResolutionCache $cache, ?int $expiresIn = null, bool $stable = true, array $roles = []): array
    {
        return $cache->rememberPermissions(self::grantee(), function (ResolutionPins $pins) use ($expiresIn, $stable, $roles): Resolution {
            $pins->roles($roles);

            return $this->resolve(['posts:read'], $expiresIn, $stable);
        });
    }

    /**
     * Count a resolution and return what it found.
     *
     * @template TValue
     *
     * @param  list<TValue>  $value
     * @param  int|null  $expiresIn
     * @param  bool  $stable
     * @return \SineMacula\Laravel\Authorization\Cache\Resolution<TValue>
     */
    private function resolve(array $value, ?int $expiresIn = null, bool $stable = true): Resolution
    {
        $this->resolutions++;

        return new Resolution($value, $expiresIn, $stable);
    }

    /**
     * Start a request: a fresh cache over the test's store.
     *
     * @param  int  $ttl
     * @return \SineMacula\Laravel\Authorization\Cache\ResolutionCache
     */
    private function request(int $ttl = 300): ResolutionCache
    {
        $cache = new ResolutionCache($this->store, $ttl, 'authorization-test');

        $this->app?->instance(ResolutionCache::class, $cache);

        return $cache;
    }

    /**
     * Return the version keys of the test's store.
     *
     * @return \SineMacula\Laravel\Authorization\Cache\VersionedStore
     */
    private function versions(): VersionedStore
    {
        return new VersionedStore($this->store, 'authorization-test');
    }

    /**
     * Record what the package writes to its log channel.
     *
     * @return \Tests\Feature\Stubs\RecordingLogger
     */
    private function recordLogs(): RecordingLogger
    {
        $logger = new RecordingLogger;

        $this->app?->instance('log', $logger);

        return $logger;
    }

    /**
     * Return the grantee every test resolves for.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function grantee(): Reference
    {
        return new Reference('user', 'user-1');
    }
}
