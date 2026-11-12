<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Events\RetrievingKey;
use Illuminate\Cache\Events\RetrievingManyKeys;
use Illuminate\Cache\Events\WritingKey;
use Illuminate\Cache\Events\WritingManyKeys;
use Illuminate\Cache\Repository;
use Illuminate\Events\Dispatcher;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\PrincipalCacheKey;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Database\BreakGlassActivations;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\FailingCacheStore;
use Tests\Feature\Stubs\NonTaggableCacheStore;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for the two-tier resolution cache: the memo, the persistent
 * entries and the versions that decide whether an entry still holds, entry
 * lifetimes, the tenant and application in the key, and a store that fails.
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
     * A chain read before its versions were pinned is read again after the pin:
     * when the tree moved meanwhile, the entry is built from the new chain but
     * not stored, so the next request resolves again and stores it.
     *
     * @return void
     */
    public function testAChainThatMovedBeforeThePinIsNotStored(): void
    {
        [$account, $org, $sibling] = \array_map(self::createTenant(...), ['account', 'org', 'sibling']);
        $tree                      = (new StubTenantTree)->put(Reference::of($account), Reference::of($org));

        $this->app?->instance(TenantTree::class, $tree);
        $this->actAsTenant($account);

        self::assertEquals([Reference::of($account), Reference::of($org)], TenantScope::currentChain()->tenants);

        $tree->put(Reference::of($account), Reference::of($sibling));

        $this->permissions($this->request());

        self::assertEquals([Reference::of($account), Reference::of($sibling)], TenantScope::currentChain()->tenants);

        $this->permissions($this->request());
        $this->permissions($this->request());

        self::assertSame(2, $this->resolutions);
    }

    /**
     * Without a store the chain held for the request is used as it is, read
     * once.
     *
     * @return void
     */
    public function testWithoutAStoreTheChainIsReadOnce(): void
    {
        $tree = new StubTenantTree;

        $this->app?->instance(TenantTree::class, $tree);
        $this->actAsTenant(self::createTenant('account'));

        $this->permissions(new ResolutionCache);

        self::assertSame(1, $tree->reads);
    }

    /**
     * A tree change made inside a transaction bumps the tenant's version again
     * once it commits, so an entry stored from the tree before the commit never
     * holds.
     *
     * @return void
     */
    public function testATreeChangeBumpsAgainOnceItsTransactionCommits(): void
    {
        $tenant  = new Reference('stub_tenant', 'org');
        $key     = $this->versions()->tenantKey($tenant);
        $cache   = $this->request();
        $pending = null;

        DB::transaction(function () use ($cache, $tenant, $key, &$pending): void {
            $cache->treeChanged($tenant);

            // A concurrent check pins the version bumped inside the
            // transaction.
            $pending = $this->versions()->tokens([$key]);
        });

        self::assertNotNull($pending);
        self::assertNotSame($pending, $this->versions()->tokens([$key]));
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
     * An entry is kept per application, so a grant made for one application is
     * never served on another.
     *
     * @return void
     */
    public function testEntriesAreKeptPerApplication(): void
    {
        foreach (['admin', 'mobile', 'admin'] as $application) {
            $this->app?->instance(SubjectResolver::class, new StubSubjectResolver(new \stdClass, null, $application));
            $this->app?->forgetInstance(ResolvedTenant::class);

            $this->permissions($this->request());
        }

        self::assertSame(2, $this->resolutions);
        self::assertIsArray($this->store->get('authorization-test:permissions:' . PrincipalCacheKey::for(self::grantee()) . ':platform:app:mobile'));
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
     * A grantee's boundaries are stored as their documents under a kind of
     * their own, keyed by the policy limits too, so they are never the
     * grantee's policies, and are hydrated back with their keys.
     *
     * @return void
     */
    public function testBoundariesAreKeptApartFromPolicies(): void
    {
        $boundary = EvaluationPolicy::fromArray(['name' => 'cap', 'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]])->withId('cap-key');
        $policy   = EvaluationPolicy::fromArray(['name' => 'readers', 'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]);

        $this->request()->rememberBoundaries(self::grantee(), fn (): Resolution => $this->resolve([$boundary]));
        $this->request()->rememberPolicies(self::grantee(), fn (): Resolution => $this->resolve([$policy]));

        $entry = $this->store->get(\str_replace(':policies:', ':boundaries:', self::policiesKey()));
        self::assertIsArray($entry);
        self::assertSame([['id' => 'cap-key', 'document' => $boundary->toArray(), 'resource' => null, 'positions' => [0]]], $entry['value']);

        $read = $this->request()->rememberBoundaries(self::grantee(), fn (): Resolution => $this->resolve([]));

        self::assertSame(2, $this->resolutions);
        self::assertEquals([$boundary], $read);
        self::assertSame('cap-key', $read[0]->id);
        self::assertEquals([$policy], $this->request()->rememberPolicies(self::grantee(), fn (): Resolution => $this->resolve([])));
    }

    /**
     * A cached policy keeps its stored key across a round trip through the
     * store, which holds each policy as its key beside its document; a policy
     * without a key comes back without one.
     *
     * @return void
     */
    public function testACachedPolicyKeepsItsKey(): void
    {
        $keyed   = EvaluationPolicy::fromArray(['name' => 'readers', 'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]])->withId('policy-key');
        $unkeyed = EvaluationPolicy::fromArray(['name' => 'writers', 'statements' => [['effect' => 'allow', 'actions' => ['posts:write']]]]);

        $this->request()->rememberPolicies(self::grantee(), fn (): Resolution => $this->resolve([$keyed, $unkeyed]));

        $entry = $this->store->get(self::policiesKey());
        self::assertIsArray($entry);
        self::assertSame([
            ['id' => 'policy-key', 'document' => $keyed->toArray(), 'resource' => null, 'positions' => [0]],
            ['id' => null, 'document' => $unkeyed->toArray(), 'resource' => null, 'positions' => [0]],
        ], $entry['value']);

        $read = $this->request()->rememberPolicies(self::grantee(), fn (): Resolution => $this->resolve([]));

        self::assertSame(1, $this->resolutions);
        self::assertEquals([$keyed, $unkeyed], $read);
        self::assertSame('policy-key', $read[0]->id);
        self::assertNull($read[1]->id);
    }

    /**
     * A policies entry is kept per set of policy limits: under changed limits
     * the entry built under the old ones misses and the policies are resolved
     * again, and under the old limits it is served again.
     *
     * @return void
     */
    public function testPoliciesAreKeptPerSetOfLimits(): void
    {
        $policy = EvaluationPolicy::fromArray(['name' => 'readers', 'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]);

        $this->request()->rememberPolicies(self::grantee(), fn (): Resolution => $this->resolve([$policy]));

        self::assertIsArray($this->store->get(self::policiesKey()));

        config(['authorization.policies.limits.statements' => 1]);

        $this->request()->rememberPolicies(self::grantee(), fn (): Resolution => $this->resolve([$policy]));

        self::assertSame(2, $this->resolutions);
        self::assertIsArray($this->store->get('authorization-test:policies:' . PrincipalCacheKey::for(self::grantee()) . ':platform:every:limits:65536.1.50.512'));

        config(['authorization.policies.limits.statements' => 100]);

        $this->request()->rememberPolicies(self::grantee(), fn (): Resolution => $this->resolve([]));
        $this->request()->rememberRoles(self::grantee(), fn (): Resolution => $this->resolve(['editor']));

        self::assertSame(3, $this->resolutions);
        self::assertIsArray($this->store->get('authorization-test:roles:' . PrincipalCacheKey::for(self::grantee()) . ':platform:every'));
    }

    /**
     * A cached policy that is not a document with its key, such as a bare
     * document in the shape stored before keys were kept, a key that is not a
     * string or a document that is missing or not an array, is discarded as
     * corrupt: it is written to the log channel and resolved again.
     *
     * @return void
     */
    public function testAPolicyEntryWithoutItsKeyIsDiscardedAsCorrupt(): void
    {
        $logger = $this->recordLogs();
        $policy = EvaluationPolicy::fromArray(['name' => 'readers', 'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]])->withId('policy-key');

        $this->request()->rememberPolicies(self::grantee(), fn (): Resolution => $this->resolve([$policy]));

        $key   = self::policiesKey();
        $entry = $this->store->get($key);
        self::assertIsArray($entry);

        $damages = [
            $policy->toArray(),
            ['id' => 42, 'document' => $policy->toArray()],
            ['id' => 'policy-key'],
            ['id' => 'policy-key', 'document' => 'not a document'],
            ['id' => 'policy-key', 'document' => null],
        ];

        foreach ($damages as $damage) {
            $this->store->put($key, [...$entry, 'value' => [$damage]], 60);

            self::assertEquals([$policy], $this->request()->rememberPolicies(self::grantee(), fn (): Resolution => $this->resolve([$policy])));
        }

        self::assertSame(1 + \count($damages), $this->resolutions);
        self::assertSame(
            \array_fill(0, \count($damages), "Authorization: discarding corrupt resolution-cache entry '{$key}' — Cached policy entry is not a policy document with its key."),
            $logger->messages(),
        );
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

        $key   = 'authorization-test:permissions:' . PrincipalCacheKey::for(self::grantee()) . ':platform:every';
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

        $key   = 'authorization-test:permissions:' . PrincipalCacheKey::for(self::grantee()) . ':platform:every';
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

        $key   = 'authorization-test:permissions:' . PrincipalCacheKey::for(self::grantee()) . ':platform:every';
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

        $key   = self::policiesKey();
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
     * A resource's policies are kept under the resource, the tenant, the
     * application and the policy limits, each with the resource it is attached
     * to, read back from the store in the next request without resolving, and
     * record no grantee's version.
     *
     * @return void
     */
    public function testAResourcesPoliciesAreKeptUnderTheResource(): void
    {
        $document = ['name' => 'sharing', 'statements' => [['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']]]];
        $policy   = EvaluationPolicy::fromArray($document)->withId('policy-key')->withResource('posts:7');
        $resource = new Reference('posts', '7');
        $key      = 'authorization-test:resource-policies:posts:7:platform:every:limits:65536.100.50.512';

        $this->request()->rememberResourcePolicies('posts', '7', function (ResolutionPins $pins) use ($policy): Resolution {
            $pins->resourcePolicies('posts');

            return $this->resolve([$policy]);
        });

        $entry = $this->store->get($key);

        self::assertIsArray($entry);
        self::assertSame([['id' => 'policy-key', 'document' => $policy->toArray(), 'resource' => 'posts:7', 'positions' => [0]]], $entry['value']);
        self::assertIsArray($entry['versions']);
        self::assertSame([$this->versions()->resourcePoliciesKey(), $this->versions()->resourcePoliciesKey('posts')], \array_keys($entry['versions']));

        $read = $this->request()->rememberResourcePolicies('posts', '7', fn (): Resolution => $this->resolve([]));

        self::assertSame(1, $this->resolutions);
        self::assertEquals([$policy], $read);
        self::assertSame('posts:7', $read[0]->resource);
        self::assertSame([], $this->request()->rememberPolicies($resource, fn (): Resolution => $this->resolve([])));
    }

    /**
     * The guardrails of a scope are kept under a kind of their own, keyed by
     * the tenant, the application and the policy limits, read back from the
     * store in the next request without resolving, and record no grantee's
     * version, only the one every guardrail entry shares.
     *
     * @return void
     */
    public function testTheGuardrailsAreKeptForTheScope(): void
    {
        $policy = EvaluationPolicy::fromArray(['name' => 'rail', 'statements' => [['effect' => 'allow', 'actions' => ['posts:*']]]])->withId('rail-key');
        $key    = 'authorization-test:guardrails:guardrails:*:platform:every:limits:65536.100.50.512';

        $this->request()->rememberGuardrails(function (ResolutionPins $pins) use ($policy): Resolution {
            $pins->guardrails();

            return $this->resolve([$policy]);
        });

        $entry = $this->store->get($key);

        self::assertIsArray($entry);
        self::assertSame([['id' => 'rail-key', 'document' => $policy->toArray(), 'resource' => null, 'positions' => [0]]], $entry['value']);
        self::assertIsArray($entry['versions']);
        self::assertSame([$this->versions()->guardrailsKey()], \array_keys($entry['versions']));

        $read = $this->request()->rememberGuardrails(fn (): Resolution => $this->resolve([]));

        self::assertSame(1, $this->resolutions);
        self::assertEquals([$policy], $read);

        $this->versions()->bump([$this->versions()->guardrailsKey()]);

        self::assertSame([], $this->request()->rememberGuardrails(fn (): Resolution => $this->resolve([])));
        self::assertSame(2, $this->resolutions);
    }

    /**
     * An entry built just below a tenant, where a grant made in the tenant
     * counts only when it reaches below, is kept apart from the tenant's own:
     * each scope writes its own key, and the tenant's never the one kept for
     * below it.
     *
     * @return void
     */
    public function testEntriesBuiltBelowATenantAreKeptApart(): void
    {
        $tenant = self::createTenant('t-1');
        $cache  = $this->request();
        $prefix = 'authorization-test:permissions:' . PrincipalCacheKey::for(self::grantee()) . ':' . $tenant->getMorphClass() . ':t-1';

        TenantScope::within($tenant, null, fn (): array => $this->permissions($cache));

        self::assertIsArray($this->store->get($prefix . ':every'));
        self::assertNull($this->store->get($prefix . ':below:every'));

        TenantScope::within($tenant, null, fn (): array => $this->permissions($cache), true);

        self::assertSame(2, $this->resolutions);
        self::assertIsArray($this->store->get($prefix . ':below:every'));

        TenantScope::within($tenant, null, fn (): array => $this->permissions($this->request()), true);

        self::assertSame(2, $this->resolutions);
    }

    /**
     * A resolution built only below a tenant writes the entry kept for below
     * the tenant, and never the one kept for the tenant itself.
     *
     * @return void
     */
    public function testAnEntryBuiltOnlyBelowATenantIsWrittenUnderTheBelowKey(): void
    {
        $tenant = self::createTenant('t-1');
        $prefix = 'authorization-test:permissions:' . PrincipalCacheKey::for(self::grantee()) . ':' . $tenant->getMorphClass() . ':t-1';

        TenantScope::within($tenant, null, fn (): array => $this->permissions($this->request()), true);

        self::assertSame(1, $this->resolutions);
        self::assertIsArray($this->store->get($prefix . ':below:every'));
        self::assertNull($this->store->get($prefix . ':every'));
    }

    /**
     * A resource policy entry whose resource is not a string is discarded as
     * corrupt and resolved again.
     *
     * @return void
     */
    public function testAResourcePolicyEntryWithAMalformedResourceIsDiscarded(): void
    {
        $logger = $this->recordLogs();
        $policy = EvaluationPolicy::fromArray(['name' => 'sharing', 'statements' => []])->withResource('posts:*');
        $key    = 'authorization-test:resource-type-policies:posts:*:platform:every:limits:65536.100.50.512';

        $this->request()->rememberResourcePolicies('posts', null, function (ResolutionPins $pins) use ($policy): Resolution {
            $pins->resourcePolicies('posts');

            return $this->resolve([$policy]);
        });

        $entry = $this->store->get($key);
        self::assertIsArray($entry);

        $this->store->put($key, [...$entry, 'value' => [['id' => null, 'document' => $policy->toArray(), 'resource' => 7]]], 60);

        self::assertEquals([$policy], $this->request()->rememberResourcePolicies('posts', null, fn (): Resolution => $this->resolve([$policy])));
        self::assertSame(2, $this->resolutions);
        self::assertCount(1, $logger->messages());
    }

    /**
     * A type alone is kept under a kind of its own, so no record's entry, not
     * even one whose key is `*`, is ever the type's.
     *
     * @return void
     */
    public function testATypeAloneIsKeptApartFromEveryRecord(): void
    {
        $type   = EvaluationPolicy::fromArray(['name' => 'type', 'statements' => []])->withResource('posts:*');
        $record = EvaluationPolicy::fromArray(['name' => 'record', 'statements' => []])->withResource('posts:*');

        $cache   = $this->request();
        $pinning = fn (EvaluationPolicy ...$policies): \Closure => function (ResolutionPins $pins) use ($policies): Resolution {
            $pins->resourcePolicies('posts');

            return $this->resolve(\array_values($policies));
        };

        self::assertEquals([$type], $cache->rememberResourcePolicies('posts', null, $pinning($type)));
        self::assertEquals([$record], $cache->rememberResourcePolicies('posts', '*', $pinning($record)));
        self::assertEquals([$type], $this->request()->rememberResourcePolicies('posts', null, $pinning()));
        self::assertSame(2, $this->resolutions);
        self::assertIsArray($this->store->get('authorization-test:resource-type-policies:posts:*:platform:every:limits:65536.100.50.512'));
        self::assertIsArray($this->store->get('authorization-test:resource-policies:posts:*:platform:every:limits:65536.100.50.512'));
    }

    /**
     * The keys of the roles a grantee reaches are kept for the grantee under
     * its own kind, read back from the store in the next request without
     * resolving, and pin the grantee's version.
     *
     * @return void
     */
    public function testAGranteesRoleKeysAreKeptForTheGrantee(): void
    {
        $grantee = new Reference('user', '1');

        self::assertSame(['role-1', 'role-2'], $this->request()->rememberRoleKeys($grantee, fn (): Resolution => $this->resolve(['role-1', 'role-2'])));
        self::assertSame(['role-1', 'role-2'], $this->request()->rememberRoleKeys($grantee, fn (): Resolution => $this->resolve([])));
        self::assertSame([], $this->request()->rememberRoles($grantee, fn (): Resolution => $this->resolve([])));
        self::assertSame(2, $this->resolutions);

        $entry = $this->store->get('authorization-test:role-keys:user:1:platform:every');

        self::assertIsArray($entry);
        self::assertIsArray($entry['versions']);
        self::assertContains($this->versions()->granteeKey($grantee), \array_keys($entry['versions']));
    }

    /**
     * The records missing from the cache are resolved together, once, and each
     * is kept under its own key, in the memo and the store, with the versions
     * pinned once; a record found is not resolved again, and one the resolution
     * leaves out is left out.
     *
     * @return void
     */
    public function testManyRecordsPoliciesAreResolvedTogetherAndKeptApart(): void
    {
        $sharing = ['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']];
        $policy  = EvaluationPolicy::fromArray(['name' => 'sharing', 'statements' => [$sharing]])->withId('policy-key');
        $asked   = [];
        $resolve = function (ResolutionPins $pins, array $missing) use ($policy, &$asked): array {
            $asked[] = $missing;

            $pins->resourcePolicies('posts');

            $resolutions = [];

            foreach (\array_diff($missing, ['9']) as $id) {
                $resolutions[$id] = $this->resolve([$policy->withResource("posts:{$id}")]);
            }

            return $resolutions;
        };

        $cache = $this->request();

        $cache->rememberResourcePolicies('posts', '1', fn (): Resolution => $this->resolve([]));

        $found = $cache->rememberResourcePoliciesMany('posts', ['1', '7', '9', 'b'], $resolve);

        self::assertSame([['7', '9', 'b']], $asked);
        self::assertSame([1, 7, 'b'], \array_keys($found));
        self::assertSame([], $found[1]);
        self::assertSame('posts:7', $found[7][0]->resource);
        self::assertSame('posts:b', $cache->rememberResourcePolicies('posts', 'b', fn (): Resolution => $this->resolve([]))[0]->resource);
        self::assertIsArray($this->store->get('authorization-test:resource-policies:posts:7:platform:every:limits:65536.100.50.512'));

        $next = $this->request();

        self::assertEquals($found[7], $next->rememberResourcePoliciesMany('posts', ['7'], $resolve)[7]);
        self::assertSame([], $next->rememberResourcePoliciesMany('posts', [], $resolve));
        self::assertSame([['7', '9', 'b']], $asked);
        self::assertSame(3, $this->resolutions);
    }

    /**
     * The store costs the same for many records as for one: the records the
     * memo does not hold are read in one read of their entries and one of the
     * versions those entries recorded, and those missing are written in one
     * write, cold or warm; a record whose entry no longer holds is resolved
     * again.
     *
     * @return void
     */
    public function testManyRecordsCostTheStoreWhatOneCosts(): void
    {
        /** @var \ArrayObject<int, string> $operations */
        $operations = new \ArrayObject;
        $events     = new Dispatcher;

        $events->listen([RetrievingKey::class, RetrievingManyKeys::class, WritingKey::class, WritingManyKeys::class], static function (object $event) use ($operations): void {
            $operations[] = $event::class;
        });

        $this->store->setEventDispatcher($events);

        $resolve = $this->resolveEach(...);
        $counted = function (string ...$ids) use ($operations, $resolve): array {
            $operations->exchangeArray([]);

            $found = $this->request()->rememberResourcePoliciesMany('posts', \array_values($ids), $resolve);

            return [$operations->getArrayCopy(), \array_map(static fn (array $policies): string => $policies[0]->resource ?? '', $found)];
        };

        $many = \array_map(strval(...), \range(1, 100));

        // The versions the records' entries share are first given a token.
        $counted('0');

        [$coldOne]              = $counted('500');
        [$coldMany, $resources] = $counted(...$many);
        [$warmOne]              = $counted('500');
        [$warmMany, $warmFound] = $counted(...$many);

        self::assertSame($coldOne, $coldMany);
        self::assertSame($warmOne, $warmMany);
        self::assertContains(WritingManyKeys::class, $coldMany);
        self::assertNotContains(WritingManyKeys::class, $warmMany);
        self::assertSame(\array_map(static fn (string $id): string => "posts:{$id}", \array_combine($many, $many)), $resources);
        self::assertSame($resources, $warmFound);
        self::assertSame(102, $this->resolutions);

        $this->versions()->bump([$this->versions()->resourcePoliciesKey('posts')]);

        $counted('1', '2');

        self::assertSame(104, $this->resolutions);

        $cache = $this->request();

        $operations->exchangeArray([]);

        $cache->rememberResourcePoliciesMany('posts', ['1'], $resolve);
        $cache->rememberResourcePoliciesMany('posts', ['1'], $resolve);

        self::assertSame([RetrievingManyKeys::class, RetrievingManyKeys::class], $operations->getArrayCopy());
    }

    /**
     * A stored entry that cannot be read back is discarded, with a warning, and
     * resolved again, as on its own.
     *
     * @return void
     */
    public function testACorruptEntryReadInBulkIsResolvedAgain(): void
    {
        $logger  = $this->recordLogs();
        $resolve = $this->resolveEach(...);

        $this->request()->rememberResourcePoliciesMany('posts', ['1', '2'], $resolve);

        $key   = 'authorization-test:resource-policies:posts:1:platform:every:limits:65536.100.50.512';
        $entry = $this->store->get($key);

        self::assertIsArray($entry);

        $this->store->put($key, [...$entry, 'value' => [['not' => 'a policy']]], 60);

        $found = $this->request()->rememberResourcePoliciesMany('posts', ['1', '2'], $resolve);

        self::assertSame(['posts:1', 'posts:2'], [$found[1][0]->resource, $found[2][0]->resource]);
        self::assertSame(3, $this->resolutions);
        self::assertCount(1, $logger->records);
    }

    /**
     * Within a batch, the tenant tree is asked each question once, unless it is
     * asked afresh; a write drops the answers, and with no batch open the tree
     * is asked every time.
     *
     * @return void
     */
    public function testATreesAnswersAreKeptForABatch(): void
    {
        $cache = $this->request();
        $asked = 0;
        $read  = static function () use (&$asked): int {
            return ++$asked;
        };

        self::assertSame([1, 2], [$cache->answerTree(['q'], $read), $cache->answerTree(['q'], $read)]);

        $answers = $cache->batch(static function () use ($cache, $read): array {
            $kept = [$cache->answerTree(['q'], $read), $cache->answerTree(['q'], $read), $cache->answerTree(['q'], $read, true)];

            $cache->invalidate([]);

            return [...$kept, $cache->answerTree(['q'], $read)];
        });

        self::assertSame([3, 3, 4, 5], $answers);
    }

    /**
     * Within a batch, the entries of each scope are kept apart as the scope
     * moves between tenants, so each is resolved once; once the batch closes, a
     * change of scope drops them again, as without one; a write within it drops
     * every scope's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABatchKeepsEachScopesEntriesUntilItCloses(): void
    {
        $cache  = new ResolutionCache;
        $tenant = self::createTenant('tenant-a');

        $this->app?->instance(ResolutionCache::class, $cache);

        $result = $cache->batch(function () use ($cache, $tenant): string {
            $this->permissions($cache);

            foreach ([1, 2] as $pass) {
                TenantScope::within($tenant, null, fn (): array => $this->permissions($cache));
                TenantScope::within(null, 'admin', fn (): array => $this->permissions($cache));
                $this->permissions($cache);
            }

            self::assertSame(3, $this->resolutions);

            $cache->invalidate([]);

            TenantScope::within($tenant, null, fn (): array => $this->permissions($cache));

            self::assertSame(4, $this->resolutions);

            return 'done';
        });

        self::assertSame('done', $result);

        TenantScope::within($tenant, null, fn (): array => $this->permissions($cache));

        self::assertSame(5, $this->resolutions);

        try {
            $cache->batch(self::failing(...));
        } catch (\RuntimeException) {
            // The batch is closed however it ends.
        }

        $this->permissions($cache);
        TenantScope::within($tenant, null, fn (): array => $this->permissions($cache));
        $this->permissions($cache);

        self::assertSame(8, $this->resolutions);
    }

    /**
     * A batch run aside, in another scope, puts back the entries of the scope
     * it is called in once it closes, however it ends, so they are not resolved
     * again; one that is not drops them, as a change of scope does, and a write
     * within one drops them for good.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABatchRunAsideKeepsTheEntriesOfTheScopeItIsCalledIn(): void
    {
        $cache  = new ResolutionCache;
        $tenant = self::createTenant('tenant-a');
        $other  = fn (): array => TenantScope::within($tenant, null, fn (): array => $this->permissions($cache));

        $this->app?->instance(ResolutionCache::class, $cache);

        $this->permissions($cache);

        self::assertNotSame([], $cache->batch($other, true));

        $this->permissions($cache);

        self::assertSame(2, $this->resolutions);

        $cache->batch($other);
        $this->permissions($cache);

        self::assertSame(4, $this->resolutions);

        $cache->batch(static function () use ($cache): void {
            $cache->invalidate([]);
        }, true);

        $this->permissions($cache);

        self::assertSame(5, $this->resolutions);

        try {
            $cache->batch(fn (): never => TenantScope::within($tenant, null, self::failing(...)), true);
        } catch (\RuntimeException) {
            // The entries are put back however the batch ends.
        }

        $this->permissions($cache);

        self::assertSame(5, $this->resolutions);
    }

    /**
     * An instance read as an identity keeps its entries apart from those of the
     * same grantee read as a subject, in the memo and the store alike, and a
     * bump of the grantee's version, which a change to its activations makes,
     * drops both.
     *
     * @return void
     */
    public function testAnIdentitysEntriesAreKeptApart(): void
    {
        $cache    = $this->request();
        $identity = self::grantee();
        $resolve  = fn (array $names): \Closure => fn (): Resolution => $this->resolve(\array_values($names));

        BreakGlassActivations::markIdentity($identity);

        self::assertSame(['posts:read'], $cache->rememberPermissions(self::grantee(), $resolve(['posts:read'])));
        self::assertSame(['posts:list'], $cache->rememberPermissions($identity, $resolve(['posts:list'])));
        self::assertSame(['posts:read'], $cache->rememberPermissions(self::grantee(), $resolve(['posts:edit'])));

        $next = $this->request();

        self::assertSame(['posts:list'], $next->rememberPermissions($identity, $resolve(['posts:edit'])));
        self::assertSame(2, $this->resolutions);
        self::assertTrue($this->store->has(PrincipalCacheKey::entry('authorization-test', 'identity-permissions', self::grantee())));

        $keys = $next->versionKeys([], [self::grantee(), new Reference('user', 'user-2')]);

        self::assertSame([$this->versions()->granteeKey(self::grantee()), $this->versions()->granteeKey(new Reference('user', 'user-2'))], $keys);

        $next->invalidate($keys);

        self::assertSame(['posts:edit'], $this->request()->rememberPermissions($identity, $resolve(['posts:edit'])));
        self::assertSame(['posts:edit'], $this->request()->rememberPermissions(self::grantee(), $resolve(['posts:edit'])));
        self::assertSame(4, $this->resolutions);
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
     * Resolve the policies attached to each record missing, one sharing policy
     * attached to each, having pinned the versions the posts' attachments
     * share, as `ResourcePolicyResolver::resolveMany()` does.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionPins  $pins
     * @param  list<string>  $missing
     * @return array<array-key, \SineMacula\Laravel\Authorization\Cache\Resolution<\SineMacula\Laravel\Authorization\Evaluation\Policy>>
     */
    private function resolveEach(ResolutionPins $pins, array $missing): array
    {
        $pins->resourcePolicies('posts');

        $sharing     = ['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']];
        $policy      = EvaluationPolicy::fromArray(['name' => 'sharing', 'statements' => [$sharing]])->withId('policy-key');
        $resolutions = [];

        foreach ($missing as $id) {
            $resolutions[$id] = $this->resolve([$policy->withResource("posts:{$id}")]);
        }

        return $resolutions;
    }

    /**
     * Start a request: a fresh cache over the test's store.
     *
     * @param  int  $ttl
     * @return \SineMacula\Laravel\Authorization\Cache\ResolutionCache
     */
    private function request(int $ttl = 300): ResolutionCache
    {
        $cache = new ResolutionCache($this->store, $ttl, 'authorization-test', activations: $this->app?->make(BreakGlassActivations::class));

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
     * Return the key of the grantee's policies entry, platform-wide, under the
     * default policy limits.
     *
     * @return string
     */
    private static function policiesKey(): string
    {
        return 'authorization-test:policies:' . PrincipalCacheKey::for(self::grantee()) . ':platform:every:limits:65536.100.50.512';
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

    /**
     * Fail, as a batch's callback may.
     *
     * @return never
     *
     * @throws \RuntimeException
     */
    private static function failing(): never
    {
        throw new \RuntimeException('failed');
    }
}
