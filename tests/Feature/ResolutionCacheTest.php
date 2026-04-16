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
use SineMacula\Laravel\Authorization\Resolvers\CachingPolicyResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature coverage for the resolution cache, its invalidation
 * listener, and the caching policy-resolver decorator.
 *
 * Covers the two tiers (in-memory memo + optional persistent
 * store), the principal-scoped invalidation path
 * (`IdentityRoleAssigned` / `IdentityPermissionGranted` /
 * `IdentityPolicyAttached` and their inverses), and the broad
 * in-memory flush triggered by role-pivot mutations.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResolutionCache::class)]
#[CoversClass(CachingPolicyResolver::class)]
#[CoversClass(InvalidateResolutionCache::class)]
#[CoversClass(AuthorizationServiceProvider::class)]
final class ResolutionCacheTest extends TestCase
{
    /**
     * Enable the persistent cache tier on the array store and
     * boot a fresh service-provider so bindings pick it up.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.cache.store', 'array');
        $config->set('authorization.cache.ttl', 0);
        $config->set('authorization.cache.prefix', 'authorization-test');

        $this->app->forgetInstance(ResolutionCache::class);
        $this->app->forgetInstance(PolicyResolver::class);

        // Re-run the registration so the fresh config is consumed.
        (new AuthorizationServiceProvider($this->app))->register();
    }

    /**
     * The in-memory memo returns the same array on subsequent
     * calls without invoking the resolver.
     *
     * @return void
     */
    public function testInMemoryMemoReturnsCachedValueWithoutInvokingResolver(): void
    {
        $cache     = $this->app->make(ResolutionCache::class);
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
     * The persistent store is populated on cold miss and read on
     * subsequent resolution from a fresh cache instance.
     *
     * @return void
     */
    public function testPersistentStoreIsReadOnColdMiss(): void
    {
        $cache     = $this->app->make(ResolutionCache::class);
        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        $cache->rememberPermissions($principal, static fn (): array => ['posts:create', 'posts:delete']);

        /** @var \Illuminate\Contracts\Cache\Repository $store */
        $store = Cache::store('array');
        $keys  = \array_filter(
            \array_keys((array) $this->extractPrivate($store->getStore(), 'storage') ?? []),
            // Laravel's tagged array entries are stored under a
            // `<hash>:<original-key>` shape; the suffix match keeps
            // the assertion faithful to the prefix-scoped entry
            // without coupling to the opaque tag hash.
            static fn (mixed $key): bool => \is_string($key) && \str_contains($key, 'authorization-test:permissions:'),
        );

        self::assertNotEmpty($keys, 'Persistent cache entry should exist under the configured prefix.');

        // New cache instance with the same store — simulates a fresh request.
        $fresh  = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');
        $result = $fresh->rememberPermissions($principal, static fn (): array => \PHPUnit\Framework\Assert::fail('Resolver should not be called on a store hit.'));

        self::assertSame(['posts:create', 'posts:delete'], $result);
    }

    /**
     * `forget()` drops every slot for the principal — memo and
     * persistent store alike.
     *
     * @return void
     */
    public function testForgetClearsEverySlotForPrincipal(): void
    {
        $cache     = $this->app->make(ResolutionCache::class);
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
     * `IdentityRoleAssigned` invalidates the principal's cached
     * role / permission slots.
     *
     * @return void
     */
    public function testIdentityRoleAssignedInvalidatesCache(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        Role::create(['id' => (string) Str::uuid(), 'name' => 'editor', 'guard_name' => 'web']);

        // Prime the cache with the current (empty) state.
        self::assertSame([], $user->getRoles());

        $user->assignRole('editor');

        self::assertSame(['editor'], $user->fresh()?->getRoles());
    }

    /**
     * `IdentityPolicyAttached` invalidates the principal's cached
     * policy slot via the caching resolver decorator.
     *
     * @return void
     */
    public function testIdentityPolicyAttachedInvalidatesCachingResolver(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        /** @var \SineMacula\Laravel\Authorization\Contracts\PolicyResolver $resolver */
        $resolver = $this->app->make(PolicyResolver::class);

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
     * `RolePermissionGranted` clears the in-memory memo tier. The
     * persistent tier is deliberately **not** cleared — the cache
     * has no reverse index from a role to the identities carrying
     * it, and flushing the whole store would wipe unrelated
     * entries. The test isolates the in-memory behaviour by using
     * a memory-only cache instance so the stale-until-TTL gap on
     * the persistent tier does not mask the flush.
     *
     * @return void
     */
    public function testRolePermissionGrantedFlushesInMemoryCache(): void
    {
        // Rebind the cache to in-memory only so the listener's
        // flush() is the only invalidation path under test.
        $this->app->instance(ResolutionCache::class, new ResolutionCache(store: null));

        $cache = $this->app->make(ResolutionCache::class);

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        $cache->rememberPermissions($principal, static fn (): array => ['stale:entry']);

        self::assertSame(['stale:entry'], $cache->rememberPermissions($principal, static fn (): array => ['live:entry']));

        $role       = Role::create(['id' => (string) Str::uuid(), 'name' => 'editor', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:create', 'guard_name' => 'web']);
        $role->givePermission($permission);

        self::assertSame(['live:entry'], $cache->rememberPermissions($principal, static fn (): array => ['live:entry']));
    }

    /**
     * On a tag-capable store, a `RolePermissionGranted` event
     * invalidates the persistent cache entry for every principal
     * tagged with the mutated role — the reverse-index gap called
     * out in ISSUES.md #68. The test assigns the role to the
     * principal (so the entry carries the role tag), primes
     * `getPermissions()` into the persistent tier, then grants a
     * new permission to the role and asserts the next read sees
     * the mutation without any manual `forget()` call.
     *
     * @return void
     */
    public function testRolePermissionGrantedInvalidatesTaggedPersistentEntry(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'editor', 'guard_name' => 'web']);

        $seed = Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:read', 'guard_name' => 'web']);
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
        $second = Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:create', 'guard_name' => 'web']);
        $role->givePermission($second);

        $permissions = $user->fresh()?->getPermissions() ?? [];
        \sort($permissions);

        self::assertSame(['posts:create', 'posts:read'], $permissions);
    }

    /**
     * On a non-tag store, `RolePermissionGranted` cannot reach a
     * reverse index into the persistent tier, so the listener
     * falls back to `flush()` on the in-memory memo and leaves
     * the persistent tier to expire on TTL (the documented
     * stale-until-TTL behaviour for File / Database drivers).
     * This is regression coverage for the non-tag branch of the
     * invalidation path — `supportsTags()` reports false, and
     * the memo flush is the only observable side effect.
     *
     * @return void
     */
    public function testRolePermissionGrantedFallsBackToMemoFlushOnNonTagStore(): void
    {
        $driver = self::makeNonTaggableDriver();

        $this->app->instance(
            ResolutionCache::class,
            new ResolutionCache(
                store: new \Illuminate\Cache\Repository($driver),
                ttl: 0,
                prefix: 'authorization-test',
            ),
        );

        $cache = $this->app->make(ResolutionCache::class);
        self::assertInstanceOf(ResolutionCache::class, $cache);
        self::assertFalse($cache->supportsTags());

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Seed the in-memory memo with a stale entry — the
        // resolver runs once and the result is memoised for the
        // lifetime of the process. The persistent tier also
        // receives the same value so we can confirm afterwards
        // that the listener does *not* touch it.
        $cache->rememberPermissions($principal, static fn (): array => ['stale:entry']);

        $keysBefore = \array_keys((array) $this->extractPrivate($driver, 'storage') ?? []);
        self::assertNotEmpty($keysBefore, 'Persistent write should populate the non-tag store.');

        $role       = Role::create(['id' => (string) Str::uuid(), 'name' => 'editor', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:create', 'guard_name' => 'web']);
        $role->givePermission($permission);

        // Persistent entries are intentionally untouched — the
        // non-tag branch leaves them to expire on TTL.
        self::assertSame(
            $keysBefore,
            \array_keys((array) $this->extractPrivate($driver, 'storage') ?? []),
            'Non-tag store must keep persistent entries after a role-pivot mutation.',
        );

        // But the memo *was* flushed — drop the persistent entry
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
     * `syncRoles()` bypasses the canonical event path but still
     * invalidates the cache — the trait calls `forget()` directly
     * after `sync()`.
     *
     * @return void
     */
    public function testSyncRolesInvalidatesCacheWithoutAssignRoleEvent(): void
    {
        Role::create(['id' => (string) Str::uuid(), 'name' => 'a', 'guard_name' => 'web']);
        Role::create(['id' => (string) Str::uuid(), 'name' => 'b', 'guard_name' => 'web']);
        Role::create(['id' => (string) Str::uuid(), 'name' => 'c', 'guard_name' => 'web']);

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
     * `getMorphClass()` / `getKey()` duck-typed pair. Regression
     * coverage for ISSUES.md #70.
     *
     * @return void
     */
    public function testNonModelPrincipalIsRoutedThroughPersistentCache(): void
    {
        $principalId = 'svc:' . Str::uuid()->toString();

        $principal = new class ($principalId) {
            public function __construct(private readonly string $id) {}

            public function getMorphClass(): string
            {
                return 'service-account';
            }

            public function getKey(): string
            {
                return $this->id;
            }
        };

        $cache = $this->app->make(ResolutionCache::class);
        $cache->rememberPermissions($principal, static fn (): array => ['svc:read', 'svc:write']);

        /** @var \Illuminate\Contracts\Cache\Repository $store */
        $store = Cache::store('array');
        $keys  = \array_filter(
            \array_keys((array) $this->extractPrivate($store->getStore(), 'storage') ?? []),
            static fn (mixed $key): bool => \is_string($key) && \str_contains($key, 'service-account:' . $principalId),
        );

        self::assertNotEmpty($keys, 'Persistent cache entry should key on the duck-typed morph class and key.');

        // A fresh cache instance reusing the same store must hit the
        // persistent tier — proves cross-request caching actually
        // works for non-Model principals.
        $fresh  = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');
        $result = $fresh->rememberPermissions(
            $principal,
            static fn (): array => \PHPUnit\Framework\Assert::fail('Resolver should not be called on a store hit.'),
        );

        self::assertSame(['svc:read', 'svc:write'], $result);
    }

    /**
     * A corrupt persistent-cache payload (wrong shape, partial
     * data) must not propagate as an exception — the entry is
     * forgotten, the resolver runs fresh, and the store is
     * rewritten with the new value. Regression coverage for
     * ISSUES.md #71.
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
            \array_keys((array) $this->extractPrivate($driver, 'storage') ?? []),
            static fn (mixed $key): bool => \is_string($key) && \str_starts_with($key, 'authorization-test:policies:'),
        );

        self::assertNotEmpty($keys);
        $policyKey = (string) \array_values($keys)[0];

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

        $result = $fresh->rememberPolicies($principal, static fn (): array => $expected);

        self::assertSame($expected, $result);

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
     * Read a private property value via reflection — tests that
     * need to inspect the array cache's internal storage.
     *
     * @param  object  $object
     * @param  string  $property
     * @return mixed
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
     * Build a bare non-taggable `Store` — an in-memory analogue of
     * the shipped File / Database drivers that the Laravel
     * `Repository` wraps unchanged (no `tags()` method on the
     * driver means `ResolutionCache::isTaggable()` returns false).
     *
     * @return \Illuminate\Contracts\Cache\Store
     */
    private static function makeNonTaggableDriver(): \Illuminate\Contracts\Cache\Store
    {
        return new class implements \Illuminate\Contracts\Cache\Store {
            /** @var array<string, mixed> */
            public array $storage = [];

            public function get($key): mixed
            {
                return $this->storage[$key] ?? null;
            }

            /**
             * @param  array<int, string>  $keys
             * @return array<string, mixed>
             */
            public function many(array $keys): array
            {
                $result = [];

                foreach ($keys as $key) {
                    $result[$key] = $this->storage[$key] ?? null;
                }

                return $result;
            }

            public function put($key, $value, $seconds): bool
            {
                $this->storage[$key] = $value;

                return true;
            }

            /**
             * @param  array<string, mixed>  $values
             * @param  mixed  $seconds
             */
            public function putMany(array $values, mixed $seconds): bool
            {
                foreach ($values as $key => $value) {
                    $this->storage[$key] = $value;
                }

                return true;
            }

            public function increment($key, $value = 1): bool|int
            {
                return false;
            }

            public function decrement($key, $value = 1): bool|int
            {
                return false;
            }

            public function forever($key, $value): bool
            {
                $this->storage[$key] = $value;

                return true;
            }

            public function touch($key, $ttl): bool
            {
                return isset($this->storage[$key]);
            }

            public function forget($key): bool
            {
                unset($this->storage[$key]);

                return true;
            }

            public function flush(): bool
            {
                $this->storage = [];

                return true;
            }

            public function getPrefix(): string
            {
                return '';
            }
        };
    }
}
