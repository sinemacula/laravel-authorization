<?php

declare(strict_types = 1);

namespace Tests\Feature\ForgettingDecisions;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for the resolution cache forgetting its memo with the decisions
 * of the request or job (N112): every entry, in every scope, set aside or not,
 * and the tenant tree's answers go, while the persistent store is left as it
 * is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResolutionCache::class)]
final class ResolutionCacheTest extends TestCase
{
    /** @var int How many times a resolution ran. */
    private int $resolutions = 0;

    /**
     * Within a batch, a change of tenant sets each scope's entries aside, to be
     * taken back once the scope is read again, while forgetting the decisions
     * drops them, in every scope.
     *
     * @return void
     */
    public function testForgettingDropsTheEntriesOfEveryScopeInABatch(): void
    {
        $cache  = $this->request();
        $tenant = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'A']);
        $inside = fn (): array => TenantScope::within($tenant, null, fn (): array => $this->permissions($cache));

        $cache->batch(function () use ($cache, $inside): void {
            $this->permissions($cache);
            $inside();
            $this->permissions($cache);
            $inside();

            self::assertSame(2, $this->resolutions);

            $cache->tenantChanged(true);

            $this->permissions($cache);
            $inside();
        });

        self::assertSame(4, $this->resolutions);
    }

    /**
     * Entries set aside for a callback run in another scope are put back once
     * it returns after a change of tenant, but not once the decisions were
     * forgotten meanwhile.
     *
     * @return void
     */
    public function testForgettingKeepsEntriesSetAsideFromBeingPutBack(): void
    {
        $cache = $this->request();

        $this->permissions($cache);

        $cache->batch(static function () use ($cache): void {
            $cache->tenantChanged();
        }, true);

        $this->permissions($cache);

        self::assertSame(1, $this->resolutions);

        $cache->batch(static function () use ($cache): void {
            $cache->tenantChanged(true);
        }, true);

        $this->permissions($cache);

        self::assertSame(2, $this->resolutions);
    }

    /**
     * The tenant tree's answers a batch keeps hold across a change of tenant,
     * and are asked again once the decisions are forgotten.
     *
     * @return void
     */
    public function testForgettingDropsTheTreesAnswers(): void
    {
        $cache = $this->request();
        $asked = 0;
        $read  = static function () use (&$asked): int {
            return ++$asked;
        };
        $ask = static fn (): int => $cache->answerTree(['ancestors', 'tenant-a'], $read);

        $answers = $cache->batch(static function () use ($cache, $ask): array {
            $answers = [$ask(), $ask()];

            $cache->tenantChanged();

            $answers[] = $ask();

            $cache->tenantChanged(true);

            $answers[] = $ask();

            return $answers;
        });

        self::assertSame([1, 1, 1, 2], $answers);
    }

    /**
     * Forgetting leaves the persistent store as it is, no entry written or
     * dropped and no version key bumped, so what was resolved is read back from
     * it rather than resolved again.
     *
     * @return void
     */
    public function testForgettingLeavesThePersistentStore(): void
    {
        $array = new ArrayStore;
        $cache = $this->request(new Repository($array));

        $this->permissions($cache);

        $held = $array->all();

        $cache->tenantChanged(true);

        self::assertSame($held, $array->all());
        self::assertSame(['posts:read'], $this->permissions($cache));
        self::assertSame(1, $this->resolutions);
    }

    /**
     * Start a request: a fresh cache over the store given, or none, bound as
     * the request's.
     *
     * @param  \Illuminate\Cache\Repository|null  $store
     * @return \SineMacula\Laravel\Authorization\Cache\ResolutionCache
     */
    private function request(?Repository $store = null): ResolutionCache
    {
        $cache = new ResolutionCache($store);

        $this->container()->instance(ResolutionCache::class, $cache);

        return $cache;
    }

    /**
     * Read the grantee's permissions through the cache, counting each
     * resolution.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCache  $cache
     * @return list<string>
     */
    private function permissions(ResolutionCache $cache): array
    {
        return $cache->rememberPermissions(new Reference('user', 'user-1'), function (): Resolution {
            $this->resolutions++;

            return new Resolution(['posts:read']);
        });
    }
}
