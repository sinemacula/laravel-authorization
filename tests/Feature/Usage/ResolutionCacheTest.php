<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use Tests\Concerns\ReviewsAccess;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\TestCase;

/**
 * Feature tests for the routes the resolution cache keeps beside a grantee's
 * permissions and policies while grant usage is tracked: in the memo and the
 * store alike, read back in another request with no query, kept under a kind of
 * their own so an entry kept without them is never read for one, and discarded
 * with their entry when they cannot be read back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResolutionCache::class)]
final class ResolutionCacheTest extends TestCase
{
    use ReviewsAccess;

    /**
     * A tracked resolution keeps its routes beside its entry, which another
     * request reads back with no query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRoutesAreKeptBesideTheEntry(): void
    {
        $store = Cache::store('array');
        $ann   = self::identity('ann');

        self::grants()->grantPermission($ann, self::permission('posts:read'));
        self::grants()->attachPolicy($ann, self::policy('no-delete'));

        $first = $this->cache($store, true);

        self::assertNull($first->routesOf('permissions', $ann));

        $ann->getPermissions();
        $ann->getPolicies();

        $permissions = $first->routesOf('permissions', $ann);
        $policies    = $first->routesOf('policies', $ann);

        self::assertNotNull($permissions);
        self::assertNotNull($policies);

        $second  = $this->cache($store, true);
        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        $ann->getPermissions();
        $ann->getPolicies();

        self::assertSame(0, $queries);
        self::assertEquals($permissions, $second->routesOf('permissions', $ann));
        self::assertEquals($policies, $second->routesOf('policies', $ann));
        self::assertCount(1, $permissions->routesFor('posts:read'));
        self::assertNull($second->routesOf('roles', $ann));
    }

    /**
     * An untracked resolution keeps no routes, and its entry is never read by a
     * tracked cache, which resolves the grantee again with its routes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEntryKeptWithoutRoutesIsNeverReadForOne(): void
    {
        $store = Cache::store('array');
        $ann   = self::identity('ann');

        self::grants()->grantPermission($ann, self::permission('posts:read'));

        $untracked = $this->cache($store, false);

        self::assertSame(['posts:read'], $ann->getPermissions());
        self::assertNull($untracked->routesOf('permissions', $ann));

        $tracked = $this->cache($store, true);
        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        self::assertSame(['posts:read'], $ann->getPermissions());
        self::assertGreaterThan(0, $queries);
        self::assertCount(1, $tracked->routesOf('permissions', $ann)?->routesFor('posts:read') ?? []);
    }

    /**
     * Routes that cannot be read back discard their entry, which is written to
     * the log and resolved afresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRoutesThatCannotBeReadBackDiscardTheEntry(): void
    {
        $store = Cache::store('array');
        $ann   = self::identity('ann');

        self::grants()->grantPermission($ann, self::permission('posts:read'));

        $this->cache($store, true);
        $ann->getPermissions();

        foreach (self::entries($store) as $key) {
            $entry = $store->get($key);

            if (!\is_array($entry) || !\array_key_exists('routes', $entry)) {
                continue;
            }

            $store->put($key, [...$entry, 'routes' => ['grants' => [], 'routes' => [], 'index' => ['posts:read' => 'corrupt']]], 300);
        }

        $logger = new RecordingLogger;

        $this->app?->instance('log', $logger);

        $cache = $this->cache($store, true);

        self::assertSame(['posts:read'], $ann->getPermissions());
        self::assertCount(1, $cache->routesOf('permissions', $ann)?->routesFor('posts:read') ?? []);
        self::assertStringContainsString('discarding corrupt resolution-cache entry', $logger->messages()[0] ?? '');
    }

    /**
     * Bind a resolution cache on the store, tracking usage or not, as a new
     * request would.
     *
     * @param  \Illuminate\Contracts\Cache\Repository  $store
     * @param  bool  $isTracking
     * @return \SineMacula\Laravel\Authorization\Cache\ResolutionCache
     */
    private function cache(Repository $store, bool $isTracking): ResolutionCache
    {
        $cache = new ResolutionCache($store, 300, 'usage-test', $isTracking);

        $this->app?->instance(ResolutionCache::class, $cache);

        return $cache;
    }

    /**
     * Return the keys of the routed entries the array store holds.
     *
     * @param  \Illuminate\Contracts\Cache\Repository  $store
     * @return list<string>
     */
    private static function entries(Repository $store): array
    {
        /** @var \Illuminate\Cache\ArrayStore $array */
        $array = $store->getStore();
        $keys  = [];

        foreach (\array_keys((new \ReflectionProperty($array, 'storage'))->getValue($array)) as $key) {
            if (!\str_contains((string) $key, '-routed:')) {
                continue;
            }

            $keys[] = (string) $key;
        }

        return $keys;
    }
}
