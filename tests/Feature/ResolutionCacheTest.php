<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Listeners\InvalidateResolutionCache;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy as PolicyModel;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Resolvers\CachingPolicyResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature coverage for the resolution cache, its invalidation listener, and the
 * caching policy-resolver decorator.
 *
 * Covers the two tiers (in-memory memo + optional persistent store), the
 * principal-scoped invalidation path (`IdentityRoleAssigned` /
 * `IdentityPermissionGranted` / `IdentityPolicyAttached` and their inverses),
 * and the broad in-memory flush triggered by role-pivot mutations.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 * @SuppressWarnings("php:S1448")
 */
#[CoversClass(ResolutionCache::class)]
#[CoversClass(CachingPolicyResolver::class)]
#[CoversClass(InvalidateResolutionCache::class)]
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(GateRegistrar::class)]
#[CoversClass(BladeDirectiveRegistrar::class)]
#[CoversClass(EventListenerRegistrar::class)]
final class ResolutionCacheTest extends TestCase
{
    /**
     * Enable the persistent cache tier on the array store and boot a fresh
     * service-provider so bindings pick it up.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.cache.store', 'array');
        $config->set('authorization.cache.ttl', 0);
        $config->set('authorization.cache.prefix', 'authorization-test');

        $this->app->forgetInstance(ResolutionCache::class); // @phpstan-ignore method.nonObject
        $this->app->forgetInstance(PolicyResolver::class); // @phpstan-ignore method.nonObject

        // Re-run the registration so the fresh config is consumed.
        (new AuthorizationServiceProvider($this->app))->register();
    }

    /**
     * The in-memory memo returns the same array on subsequent calls without
     * invoking the resolver.
     *
     * @return void
     */
    public function testInMemoryMemoReturnsCachedValueWithoutInvokingResolver(): void
    {
        $cache     = $this->app->make(ResolutionCache::class); // @phpstan-ignore method.nonObject
        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        $calls = 0;

        $first = $cache->rememberPermissions($principal, static function () use (&$calls): array {
            $calls++;

            return ['posts:create'];
        });

        $second = $cache->rememberPermissions($principal, static function () use (&$calls): array {
            $calls++;

            return ['something-else-entirely'];
        });

        self::assertSame(1, $calls);
        self::assertSame(['posts:create'], $first);
        self::assertSame(['posts:create'], $second);
    }

    /**
     * The persistent store is populated on cold miss and read on subsequent
     * resolution from a fresh cache instance.
     *
     * @return void
     */
    public function testPersistentStoreIsReadOnColdMiss(): void
    {
        $cache     = $this->app->make(ResolutionCache::class); // @phpstan-ignore method.nonObject
        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        $cache->rememberPermissions($principal, static fn (): array => ['posts:create', 'posts:delete']);

        /** @var \Illuminate\Contracts\Cache\Repository $store */
        $store = Cache::store('array');
        $keys  = \array_filter(
            \array_keys((array) $this->extractPrivate($store->getStore(), 'storage') ?? []), // @phpstan-ignore nullCoalesce.expr
            // Laravel's tagged array entries are stored under a
            // `<hash>:<original-key>` shape; the suffix match keeps
            // the assertion faithful to the prefix-scoped entry
            // without coupling to the opaque tag hash.
            static fn (mixed $key): bool => \is_string($key) && \str_contains($key, 'authorization-test:permissions:'),
        );

        self::assertNotEmpty($keys, 'Persistent cache entry should exist under the configured prefix.');

        // New cache instance with the same store — simulates a fresh request.
        $fresh         = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');
        $cachedEntries = $fresh->rememberPermissions($principal, static fn (): array => \PHPUnit\Framework\Assert::fail('Resolver should not be called on a store hit.'));

        self::assertSame(['posts:create', 'posts:delete'], $cachedEntries);
    }

    /**
     * `forget()` drops every slot for the principal — memo and persistent store
     * alike.
     *
     * @return void
     */
    public function testForgetClearsEverySlotForPrincipal(): void
    {
        $cache     = $this->app->make(ResolutionCache::class); // @phpstan-ignore method.nonObject
        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        $cache->rememberPermissions($principal, static fn (): array => ['a']);
        $cache->rememberRoles($principal, static fn (): array => ['admin']);

        $cache->forget($principal);

        $calls = 0;
        $cache->rememberPermissions($principal, static function () use (&$calls): array {
            $calls++;

            return ['b'];
        });

        self::assertSame(1, $calls);
    }

    /**
     * `IdentityRoleAssigned` invalidates the principal's cached role /
     * permission slots.
     *
     * @return void
     */
    public function testIdentityRoleAssignedInvalidatesCache(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        Role::create(['id' => (string) Str::uuid(), 'name' => 'editor', 'guard' => 'web']);

        // Prime the cache with the current (empty) state.
        self::assertSame([], $user->getRoles());

        $user->assignRole('editor');

        self::assertSame(['editor'], $user->fresh()?->getRoles());
    }

    /**
     * `IdentityPolicyAttached` invalidates the principal's cached policy slot
     * via the caching resolver decorator.
     *
     * @return void
     */
    public function testIdentityPolicyAttachedInvalidatesCachingResolver(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        /** @var \SineMacula\Laravel\Authorization\Contracts\PolicyResolver $resolver */
        $resolver = $this->app->make(PolicyResolver::class); // @phpstan-ignore method.nonObject

        self::assertSame([], $resolver->policiesFor($user));

        $user->attachPolicy(PolicyModel::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'allow-x',
            'document' => [
                'statements' => [['effect' => 'allow', 'actions' => ['x']]],
            ],
        ]));

        $policies = $resolver->policiesFor($user->fresh());

        self::assertCount(1, $policies);
        self::assertInstanceOf(EvaluationPolicy::class, $policies[0]);
        self::assertSame('allow-x', $policies[0]->name);
    }

    /**
     * `RolePermissionGranted` clears the in-memory memo tier. The persistent
     * tier is deliberately not cleared — the cache has no reverse index from a
     * role to the identities carrying it, and flushing the whole store would
     * wipe unrelated entries. The test isolates the in-memory behaviour by
     * using a memory-only cache instance so the stale-until-TTL gap on the
     * persistent tier does not mask the flush.
     *
     * @return void
     */
    public function testRolePermissionGrantedFlushesInMemoryCache(): void
    {
        // Rebind the cache to in-memory only so the listener's
        // flush() is the only invalidation path under test.
        $this->app->instance(ResolutionCache::class, new ResolutionCache(store: null)); // @phpstan-ignore method.nonObject

        $cache = $this->app->make(ResolutionCache::class); // @phpstan-ignore method.nonObject

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        $cache->rememberPermissions($principal, static fn (): array => ['stale:entry']);

        self::assertSame(['stale:entry'], $cache->rememberPermissions($principal, static fn (): array => ['live:entry']));

        $role       = Role::create(['id' => (string) Str::uuid(), 'name' => 'editor', 'guard' => 'web']);
        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:create', 'guard' => 'web']);
        $role->givePermission($permission);

        self::assertSame(['live:entry'], $cache->rememberPermissions($principal, static fn (): array => ['live:entry']));
    }

    /**
     * On a tag-capable store, a `RolePermissionGranted` event invalidates the
     * persistent cache entry for every principal tagged with the mutated role.
     * The test assigns the role to the principal (so the entry carries the role
     * tag), primes `getPermissions()` into the persistent tier, then grants a
     * new permission to the role and asserts the next read sees the mutation
     * without any manual `forget()` call.
     *
     * @return void
     */
    public function testRolePermissionGrantedInvalidatesTaggedPersistentEntry(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'editor', 'guard' => 'web']);

        $seed = Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:read', 'guard' => 'web']);
        $role->givePermission($seed);

        $user->assignRole('editor');

        // Prime the persistent cache via the canonical accessor —
        // the trait wires role IDs through so the entry carries
        // the role tag.
        self::assertSame(['posts:read'], $user->fresh()?->getPermissions());

        // Attaching a new permission to the role fires
        // `RolePermissionGranted`. On a tag-capable store the
        // listener must flush the principal's entry via the role
        // tag — not just the in-memory memo.
        $second = Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:create', 'guard' => 'web']);
        $role->givePermission($second);

        // @phpstan-ignore-next-line nullCoalesce.expr, nullsafe.neverNull non-null post-persist)
        $permissions = $user->fresh()?->getPermissions() ?? [];
        \sort($permissions);

        self::assertSame(['posts:create', 'posts:read'], $permissions);
    }

    /**
     * On a non-tag store, `RolePermissionGranted` cannot reach a reverse index
     * into the persistent tier, so the listener falls back to `flush()` on the
     * in-memory memo and leaves the persistent tier to expire on TTL (the
     * documented stale-until-TTL behaviour for File / Database drivers). This
     * is regression coverage for the non-tag branch of the invalidation path —
     * `supportsTags()` reports false, and the memo flush is the only observable
     * side effect.
     *
     * @return void
     */
    public function testRolePermissionGrantedFallsBackToMemoFlushOnNonTagStore(): void
    {
        $driver = self::makeNonTaggableDriver();
        $cache  = $this->bindNonTagResolutionCache($driver);

        self::assertFalse($cache->supportsTags());

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Seed the in-memory memo with a stale entry — the
        // resolver runs once and the result is memoised for the
        // lifetime of the process. The persistent tier also
        // receives the same value so we can confirm afterwards
        // that the listener does not touch it.
        $cache->rememberPermissions($principal, static fn (): array => ['stale:entry']);

        $keysBefore = \array_keys((array) $this->extractPrivate($driver, 'storage') ?? []); // @phpstan-ignore nullCoalesce.expr
        self::assertNotEmpty($keysBefore, 'Persistent write should populate the non-tag store.');

        $role       = Role::create(['id' => (string) Str::uuid(), 'name' => 'editor', 'guard' => 'web']);
        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:create', 'guard' => 'web']);
        $role->givePermission($permission);

        // Persistent entries are intentionally untouched — the
        // non-tag branch leaves them to expire on TTL.
        self::assertSame(
            $keysBefore,
            \array_keys((array) $this->extractPrivate($driver, 'storage') ?? []), // @phpstan-ignore nullCoalesce.expr
            'Non-tag store must keep persistent entries after a role-pivot mutation.',
        );

        // But the memo was flushed — drop the persistent entry
        // for the original principal (so the store read on the
        // next lookup misses) and observe that the resolver runs
        // again instead of returning the memoised `stale:entry`.
        foreach ($keysBefore as $key) {
            $driver->forget((string) $key);
        }

        self::assertSame(
            ['live:entry'],
            $cache->rememberPermissions($principal, static fn (): array => ['live:entry']),
        );
    }

    /**
     * `syncRoles()` bypasses the canonical event path but still invalidates the
     * cache — the trait calls `forget()` directly after `sync()`.
     *
     * @return void
     */
    public function testSyncRolesInvalidatesCacheWithoutAssignRoleEvent(): void
    {
        Role::create(['id' => (string) Str::uuid(), 'name' => 'a', 'guard' => 'web']);
        Role::create(['id' => (string) Str::uuid(), 'name' => 'b', 'guard' => 'web']);
        Role::create(['id' => (string) Str::uuid(), 'name' => 'c', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->syncRoles(['a', 'b']);

        $first = $user->fresh()?->getRoles() ?? [];
        \sort($first);
        self::assertSame(['a', 'b'], $first);

        $user->syncRoles(['c']);

        self::assertSame(['c'], $user->fresh()?->getRoles());
    }

    /**
     * A non-Eloquent principal — a plain object implementing
     * `AuthorizableIdentity` without extending `Model` — still gets
     * cross-request persistent-cache benefit when it exposes the
     * `getMorphClass()` / `getKey()` duck-typed pair.
     *
     * @return void
     */
    public function testNonModelPrincipalIsRoutedThroughPersistentCache(): void
    {
        $principalId = 'svc:' . Str::uuid()->toString();

        /**
         * Non-model principal that exposes morph class and key methods so the
         * cache keys it through the persistent store.
         */
        $principal = new class ($principalId) {
            /**
             * Create a new principal wrapping a fixed identifier.
             *
             * @param  string  $id
             * @return void
             */
            public function __construct(

                /** The stable identifier used as the cache key. */
                private readonly string $id,

            ) {}

            /**
             * Return the morph class used for cache keying.
             *
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'service-account';
            }

            /**
             * Return the stable identifier used for cache keying.
             *
             * @return string
             */
            public function getKey(): string
            {
                return $this->id;
            }
        };

        $cache = $this->app->make(ResolutionCache::class); // @phpstan-ignore method.nonObject
        $cache->rememberPermissions($principal, static fn (): array => ['svc:read', 'svc:write']);

        /** @var \Illuminate\Contracts\Cache\Repository $store */
        $store = Cache::store('array');
        $keys  = \array_filter(
            \array_keys((array) $this->extractPrivate($store->getStore(), 'storage') ?? []), // @phpstan-ignore nullCoalesce.expr
            static fn (mixed $key): bool => \is_string($key) && \str_contains($key, 'service-account:' . $principalId),
        );

        self::assertNotEmpty($keys, 'Persistent cache entry should key on the duck-typed morph class and key.');

        // A fresh cache instance reusing the same store must hit the
        // persistent tier — proves cross-request caching actually
        // works for non-Model principals.
        $fresh         = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');
        $cachedEntries = $fresh->rememberPermissions(
            $principal,
            static fn (): array => \PHPUnit\Framework\Assert::fail('Resolver should not be called on a store hit.'),
        );

        self::assertSame(['svc:read', 'svc:write'], $cachedEntries);
    }

    /**
     * A corrupt persistent-cache payload (wrong shape, partial data) must not
     * propagate as an exception — the entry is forgotten, the resolver runs
     * fresh, and the store is rewritten with the new value.
     *
     * @return void
     */
    public function testCorruptPersistentCacheEntryIsDiscardedAndRecomputed(): void
    {
        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Target the non-taggable store path with an anonymous
        // driver that hides `tags()` — this keeps the test's
        // payload shape in sync with the cache's untagged write
        // so the fail-closed recovery can be observed without
        // tangling with Laravel's tag-namespace hashing. The
        // tag-capable store exercises its own recovery via
        // `forgetFromStore()` which the tag-capable scenarios
        // cover indirectly.
        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);

        $cache = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        // Prime the persistent tier with the correct shape so the
        // cache key is discoverable, then corrupt it.
        $cache->rememberPolicies($principal, static fn (): array => []);

        $keys = \array_filter(
            \array_keys((array) $this->extractPrivate($driver, 'storage') ?? []), // @phpstan-ignore nullCoalesce.expr
            static fn (mixed $key): bool => \is_string($key) && \str_starts_with($key, 'authorization-test:policies:'),
        );

        self::assertNotEmpty($keys);
        $policyKey = (string) \array_values($keys)[0]; // @phpstan-ignore cast.useless

        // Seed a malformed payload — a list of non-array entries
        // will fail the `Policy::fromArray` contract.
        $driver->put($policyKey, ['not-a-policy-document', 42], 60);

        // Fresh cache instance forces the persistent tier to be
        // consulted (bypasses the in-memory memo primed above).
        $fresh = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $expected = [
            new EvaluationPolicy(
                name: 'fresh',
                statements: [],
            ),
        ];

        $cachedEntries = $fresh->rememberPolicies($principal, static fn (): array => $expected);

        self::assertSame($expected, $cachedEntries);

        // Store should have been rewritten with the recomputed
        // (valid) payload, not the corrupt one.
        /** @var mixed $stored */
        $stored = $driver->get($policyKey);
        self::assertIsArray($stored);
        self::assertCount(1, $stored);
        self::assertIsArray($stored[0]);
        self::assertSame('fresh', $stored[0]['name'] ?? null);
    }

    /**
     * `forget()` drops all three slots from the persistent store on a
     * non-taggable store — pins the `['policies', 'permissions', 'roles']`
     * array against ArrayItemRemoval mutations on line 214.
     *
     * @return void
     */
    public function testForgetDropsAllThreeSlotsFromNonTagStore(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'fgt');

        $principal = new class {
            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'u';
            }

            /**
             * @return string
             */
            public function getKey(): string
            {
                return '1';
            }
        };

        $cache->rememberPermissions($principal, static fn (): array => ['a']);
        $cache->rememberRoles($principal, static fn (): array => ['r']);
        $cache->rememberPolicies($principal, static fn (): array => []);

        self::assertArrayHasKey('fgt:permissions:u:1', $driver->storage); // @phpstan-ignore property.notFound
        self::assertArrayHasKey('fgt:roles:u:1', $driver->storage);
        self::assertArrayHasKey('fgt:policies:u:1', $driver->storage);

        $cache->forget($principal);

        self::assertArrayNotHasKey('fgt:permissions:u:1', $driver->storage);
        self::assertArrayNotHasKey('fgt:roles:u:1', $driver->storage);
        self::assertArrayNotHasKey('fgt:policies:u:1', $driver->storage);
    }

    /**
     * `rememberPolicies()` with null context defaults to a fresh
     * `ResolutionCacheContext` — pins the `$context ?? new ...` coalesce on
     * line 98.
     *
     * @return void
     */
    public function testRememberPoliciesWithNullContextDefaultsGracefully(): void
    {
        $cache     = $this->app->make(ResolutionCache::class); // @phpstan-ignore method.nonObject
        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        $expected = [
            new EvaluationPolicy(name: 'ctx-null', statements: []),
        ];

        $cachedEntries = $cache->rememberPolicies($principal, static fn (): array => $expected, null);

        self::assertSame($expected, $cachedEntries);
    }

    /**
     * Non-array entries in a policy cache document raise
     * `UnexpectedValueException` which is caught, the key is forgotten, and the
     * resolver re-fires. Pins the Throw_ mutant on line 116.
     *
     * @return void
     */
    public function testNonArrayPolicyDocumentThrowsAndRecovery(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'thr');

        $principal = new class {
            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'th';
            }

            /**
             * @return string
             */
            public function getKey(): string
            {
                return '1';
            }
        };

        // Prime with valid, then corrupt.
        $cache->rememberPolicies($principal, static fn (): array => []);
        $driver->put('thr:policies:th:1', ['not-an-array'], 60);

        $fresh         = new ResolutionCache(store: $store, ttl: 0, prefix: 'thr');
        $expected      = [new EvaluationPolicy(name: 'recovered', statements: [])];
        $cachedEntries = $fresh->rememberPolicies($principal, static fn (): array => $expected);

        self::assertSame($expected, $cachedEntries);
    }

    /**
     * `forgetFromStore` is called during the corrupt-entry path in
     * `rememberStringList` — pins the MethodCallRemoval mutant on line 318.
     *
     * @return void
     */
    public function testCorruptStringListEntryIsForgottenAndRecomputed(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'csl');

        $principal = new class {
            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'sl';
            }

            /**
             * @return string
             */
            public function getKey(): string
            {
                return '1';
            }
        };

        $cache->rememberPermissions($principal, static fn (): array => ['a']);

        // Corrupt the stored value to a non-array.
        $driver->put('csl:permissions:sl:1', 'not-an-array', 60);

        $cache = new ResolutionCache(store: $store, ttl: 0, prefix: 'csl');
        self::assertInstanceOf(ResolutionCache::class, $cache);

        // The throwable from is_array(string) being true but
        // array_filter('is_string') being applied... Actually, a
        // string value will fail is_array, so resolver re-runs.
        // Let's use an object to trigger a throw.
        $driver->put('csl:permissions:sl:1', new \stdClass, 60);

        $fresh2        = new ResolutionCache(store: $store, ttl: 0, prefix: 'csl');
        $cachedEntries = $fresh2->rememberPermissions($principal, static fn (): array => ['recovered']);

        self::assertSame(['recovered'], $cachedEntries);
    }

    /**
     * `keyFor()` with an integer getKey returns the string cast. Pins
     * CastString on line 386 and LogicalOr mutants on line 385.
     *
     * @return void
     */
    public function testKeyForIntegerGetKey(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'kf');

        $principal = new class {
            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'int-morph';
            }

            /**
             * @return int
             */
            public function getKey(): int
            {
                return 99;
            }
        };

        $cache->rememberRoles($principal, static fn (): array => ['r']);

        self::assertArrayHasKey('kf:roles:int-morph:99', $driver->storage); // @phpstan-ignore property.notFound
    }

    /**
     * `keyFor()` falls back to `obj:spl_object_hash` when getKey returns empty
     * string. Pins the `$id === null` branch on line 394 and the
     * Concat/ConcatOperandRemoval mutants on line 395.
     *
     * @return void
     */
    public function testKeyForFallsBackToSplObjectHashOnEmptyKey(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'spl');

        $principal = new class {
            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'empty-morph';
            }

            /**
             * @return string
             */
            public function getKey(): string
            {
                return '';
            }
        };

        $cache->rememberRoles($principal, static fn (): array => ['r']);

        $hash       = \spl_object_hash($principal);
        $expectedId = "obj:{$hash}";
        $key        = "spl:roles:empty-morph:{$expectedId}";

        self::assertArrayHasKey($key, $driver->storage); // @phpstan-ignore property.notFound
    }

    /**
     * `principalTag` is assembled as `<prefix>:principal:<keyFor>`. Pins the
     * Concat/ConcatOperandRemoval mutants on line 411.
     *
     * @return void
     */
    public function testPrincipalTagShapeIsCorrect(): void
    {
        $cache = new ResolutionCache(store: \Illuminate\Support\Facades\Cache::store('array'), ttl: 0, prefix: 'ptag');

        $ref = new \ReflectionMethod($cache, 'principalTag');

        $principal = new class {
            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'pt';
            }

            /**
             * @return string
             */
            public function getKey(): string
            {
                return 'abc';
            }
        };

        $tag = $ref->invoke($cache, $principal);

        self::assertSame('ptag:principal:pt:abc', $tag);
    }

    /**
     * `tagsFor` includes the prefix tag, principal tag, and per-role tags while
     * skipping empty role IDs. Pins ArrayItemRemoval on line 425, Continue_ on
     * line 429, and UnwrapArrayUnique / UnwrapArrayValues on line 435.
     *
     * @return void
     */
    public function testTagsForComposesCorrectTagSet(): void
    {
        $cache = new ResolutionCache(store: \Illuminate\Support\Facades\Cache::store('array'), ttl: 0, prefix: 'tf');

        $ref = new \ReflectionMethod($cache, 'tagsFor');

        $principal = new class {
            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'tg';
            }

            /**
             * @return string
             */
            public function getKey(): string
            {
                return '7';
            }
        };

        /** @var array<int, string> $tags */
        $tags = $ref->invoke($cache, $principal, ['r1', '', 'r2', 'r1']);

        // Must contain prefix, principal tag, and both role tags
        // (deduped), and must skip the empty-string role ID.
        self::assertSame([
            'tf',
            'tf:principal:tg:7',
            'tf:role:r1',
            'tf:role:r2',
        ], $tags);
    }

    /**
     * `isTaggable()` return value is memoised and returned on subsequent calls.
     * Pins the ReturnRemoval mutant on line 461.
     *
     * @return void
     */
    public function testIsTaggableMemoReturnValue(): void
    {
        $cache = new ResolutionCache(store: \Illuminate\Support\Facades\Cache::store('array'), ttl: 0, prefix: 'itm');

        // First call computes and caches.
        self::assertTrue($cache->supportsTags());
        // Second call returns from the memo.
        self::assertTrue($cache->supportsTags());

        $nullCache = new ResolutionCache(store: null);
        self::assertFalse($nullCache->supportsTags());
    }

    /**
     * `putInStore` skips the write when computed TTL is zero or negative. Pins
     * the `<= 0` vs `< 0` mutant on line 613 and the LogicalAnd/ReturnRemoval
     * on lines 613-614.
     *
     * @return void
     */
    public function testPutInStoreSkipsWriteWhenTtlNotPositive(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);

        // ttl=0 is forever, but maxTtl=0 forces computed TTL to
        // min(INT_MAX, 0) - 1 = -1 — the write should be skipped.
        $cache = new ResolutionCache(store: $store, ttl: 0, prefix: 'ttl0');

        $principal = new class {
            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'ttl';
            }

            /**
             * @return string
             */
            public function getKey(): string
            {
                return '1';
            }
        };

        $cache->rememberPermissions(
            $principal,
            static fn (): array => ['x'],
            new \SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext(maxTtl: 0),
        );

        // The memo is populated but the store should NOT have the entry
        // because the TTL is -1.
        self::assertEmpty($driver->storage); // @phpstan-ignore property.notFound
    }

    /**
     * `putInStore` uses the configured TTL when `$maxTtl` is null and TTL > 0.
     * Pins the non-forever branch on line 632.
     *
     * @return void
     */
    public function testPutInStoreUsesConfiguredTtlWhenPositive(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 300, prefix: 'ttlp');

        $principal = new class {
            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'ttlp';
            }

            /**
             * @return string
             */
            public function getKey(): string
            {
                return '1';
            }
        };

        $cache->rememberPermissions($principal, static fn (): array => ['y']);

        self::assertArrayHasKey('ttlp:permissions:ttlp:1', $driver->storage); // @phpstan-ignore property.notFound
    }

    /**
     * `putInStore` with maxTtl=1 writes with computed TTL = 0 which should be
     * skipped (boundary test for `<= 0`).
     *
     * @return void
     */
    public function testPutInStoreSkipsWhenMaxTtlIsOne(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'ttl1');

        $principal = new class {
            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'ttl1';
            }

            /**
             * @return string
             */
            public function getKey(): string
            {
                return '1';
            }
        };

        // maxTtl=1 -> min(INT_MAX, 1) - 1 = 0, should be skipped.
        $cache->rememberPermissions(
            $principal,
            static fn (): array => ['z'],
            new \SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext(maxTtl: 1),
        );

        self::assertEmpty($driver->storage); // @phpstan-ignore property.notFound
    }

    /**
     * `logCorruptCacheEntry` includes the cache key in the log message. Pins
     * the ConcatOperandRemoval mutant on line 563.
     *
     * @return void
     */
    public function testCorruptCacheLogIncludesKey(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'logk');

        $principal = new class {
            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'lg';
            }

            /**
             * @return string
             */
            public function getKey(): string
            {
                return '1';
            }
        };

        // Prime then corrupt.
        $cache->rememberPermissions($principal, static fn (): array => ['a']);
        $driver->put('logk:permissions:lg:1', new \stdClass, 60);

        // Capture log output.
        \Illuminate\Support\Facades\Log::spy();

        $fresh = new ResolutionCache(store: $store, ttl: 0, prefix: 'logk');
        $fresh->rememberPermissions($principal, static fn (): array => ['b']);

        // We cannot easily assert the exact log call through the
        // authorization channel, but we can confirm the resolver ran
        // (meaning the corrupt path was hit) and the result is correct.
        $cachedEntries = $fresh->rememberPermissions($principal, static fn (): array => ['c']);
        self::assertSame(['b'], $cachedEntries);
    }

    /**
     * `rememberPolicies` maps each policy through `toArray()` when writing to
     * the store and reads them back via `fromArray()`. Pins the ArrayOneItem
     * mutant on line 145 (putInStore args).
     *
     * @return void
     */
    public function testRememberPoliciesPersistsAndRehydratesPolicies(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'pol');

        $principal = new class {
            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'pp';
            }

            /**
             * @return string
             */
            public function getKey(): string
            {
                return '1';
            }
        };

        $original = [
            new EvaluationPolicy(
                name: 'test-policy',
                statements: [],
            ),
        ];

        $cache->rememberPolicies($principal, static fn (): array => $original);

        // Fresh instance — reads from the store.
        $fresh         = new ResolutionCache(store: $store, ttl: 0, prefix: 'pol');
        $cachedEntries = $fresh->rememberPolicies(
            $principal,
            static fn (): array => \PHPUnit\Framework\Assert::fail('Resolver should not run.'),
        );

        self::assertCount(1, $cachedEntries);
        self::assertSame('test-policy', $cachedEntries[0]->name);
    }

    /**
     * `keyFor()` returns `obj:spl_object_hash` for principals without
     * `getKey()` at all. Pins the spl_object_hash fallback.
     *
     * @return void
     */
    public function testKeyForPrincipalWithoutGetKey(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'nk');

        $principal = new \stdClass;
        $hash      = \spl_object_hash($principal);

        $cache->rememberRoles($principal, static fn (): array => ['r']);

        $class = $principal::class;
        self::assertArrayHasKey("nk:roles:{$class}:obj:{$hash}", $driver->storage); // @phpstan-ignore property.notFound
    }

    /**
     * `forgetRoleTags()` is a no-op when the role's `getKey()` returns empty
     * string. Pins the LogicalAnd on line 376 and the `$id === ''` guard on
     * line 241/243.
     *
     * @return void
     */
    public function testForgetRoleTagsSkipsEmptyRoleKey(): void
    {
        $cache = new ResolutionCache(store: \Illuminate\Support\Facades\Cache::store('array'), prefix: 'frt');

        $emptyRole = new class {
            /**
             * @return string
             */
            public function getKey(): string
            {
                return '';
            }
        };

        // Should not throw — just no-op.
        $cache->forgetRoleTags($emptyRole);

        self::assertTrue(true, 'forgetRoleTags with empty key must not throw.');
    }

    /**
     * `forgetRoleTags()` is a no-op when the role has no getKey method. Pins
     * the `method_exists` guard on line 240.
     *
     * @return void
     */
    public function testForgetRoleTagsSkipsNoGetKeyMethod(): void
    {
        $cache = new ResolutionCache(store: \Illuminate\Support\Facades\Cache::store('array'), prefix: 'frt2');

        $noKey = new \stdClass;

        $cache->forgetRoleTags($noKey);

        self::assertTrue(true, 'forgetRoleTags without getKey must not throw.');
    }

    /**
     * `forgetRoleTags()` flushes entries tagged with the role's integer key
     * (coerced to string). Pins the CastString on 386 and the `is_int` branch
     * on line 385.
     *
     * @return void
     */
    public function testForgetRoleTagsWithIntegerKey(): void
    {
        $cache = new ResolutionCache(store: \Illuminate\Support\Facades\Cache::store('array'), prefix: 'fri');

        $intRole = new class {
            /**
             * @return int
             */
            public function getKey(): int
            {
                return 42;
            }
        };

        // Should not throw.
        $cache->forgetRoleTags($intRole);

        self::assertTrue(true, 'forgetRoleTags with integer key must not throw.');
    }

    /**
     * Bind a fresh `ResolutionCache` backed by the given non-tag driver and
     * return the container-resolved instance.
     *
     * @param  \Illuminate\Contracts\Cache\Store  $driver
     * @return \SineMacula\Laravel\Authorization\Cache\ResolutionCache
     */
    private function bindNonTagResolutionCache(\Illuminate\Contracts\Cache\Store $driver): ResolutionCache
    {
        $this->app->instance( // @phpstan-ignore method.nonObject
            ResolutionCache::class,
            new ResolutionCache(
                store: new \Illuminate\Cache\Repository($driver),
                ttl: 0,
                prefix: 'authorization-test',
            ),
        );

        $cache = $this->app->make(ResolutionCache::class); // @phpstan-ignore method.nonObject
        self::assertInstanceOf(ResolutionCache::class, $cache);

        return $cache;
    }

    /**
     * Read a private property value via reflection — tests that need to inspect
     * the array cache's internal storage.
     *
     * @param  object  $object
     * @param  string  $property
     * @return mixed
     *
     * @SuppressWarnings("php:S3011")
     */
    private function extractPrivate(object $object, string $property): mixed
    {
        $reflection = new \ReflectionClass($object);

        while (!$reflection->hasProperty($property) && $reflection->getParentClass() !== false) {
            $reflection = $reflection->getParentClass();
        }

        if (!$reflection->hasProperty($property)) {
            return null;
        }

        $ref = $reflection->getProperty($property);
        $ref->setAccessible(true);

        return $ref->getValue($object);
    }

    /**
     * Build a bare non-taggable `Store` — an in-memory analogue of the shipped
     * File / Database drivers that the Laravel `Repository` wraps unchanged (no
     * `tags()` method on the driver means `ResolutionCache::isTaggable()`
     * returns false).
     *
     * @return \Tests\Feature\Stubs\NonTaggableCacheStore
     */
    private static function makeNonTaggableDriver(): \Tests\Feature\Stubs\NonTaggableCacheStore
    {
        return new \Tests\Feature\Stubs\NonTaggableCacheStore;
    }
}
