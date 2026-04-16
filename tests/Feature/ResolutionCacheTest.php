<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\PolicyRepository;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Listeners\InvalidateResolutionCache;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy as PolicyModel;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Repositories\CachingPolicyRepository;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature coverage for the resolution cache, its invalidation
 * listener, and the caching policy-repository decorator.
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
#[CoversClass(CachingPolicyRepository::class)]
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
        $this->app->forgetInstance(PolicyRepository::class);

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
            static fn (mixed $key): bool => \is_string($key) && \str_starts_with($key, 'authorization-test:permissions:'),
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
     * policy slot via the caching repository decorator.
     *
     * @return void
     */
    public function testIdentityPolicyAttachedInvalidatesCachingRepository(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        /** @var \SineMacula\Laravel\Authorization\Contracts\PolicyRepository $repository */
        $repository = $this->app->make(PolicyRepository::class);

        self::assertSame([], $repository->policiesFor($user));

        $user->attachPolicy(PolicyModel::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'allow-x',
            'document' => [
                'statements' => [['effect' => 'allow', 'actions' => ['x']]],
            ],
        ]));

        $policies = $repository->policiesFor($user->fresh());

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
}
