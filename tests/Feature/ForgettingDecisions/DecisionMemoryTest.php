<?php

declare(strict_types = 1);

namespace Tests\Feature\ForgettingDecisions;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionMemory;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Concerns\RefusesThePackage;
use Tests\Feature\Stubs\ChangingSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for `DecisionMemory`, what the request or job remembers towards
 * its decisions and the one call that has it forgotten (N112): the last
 * decision, the resolution memo and the tenant the request resolved, with a
 * generation that moves on each time, for the request or job alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DecisionMemory::class)]
final class DecisionMemoryTest extends TestCase
{
    use RefusesThePackage;

    /** @var int How many times a resolution ran. */
    private int $resolutions = 0;

    /**
     * The memory belongs to the request or job: the same one is returned
     * throughout it, bound scoped on first use, and the next starts afresh at
     * the first generation.
     *
     * @return void
     */
    public function testTheMemoryBelongsToTheRequestOrJob(): void
    {
        $app = $this->container();

        self::assertFalse($app->bound(DecisionMemory::class));

        $memory = DecisionMemory::current();

        self::assertSame($memory, DecisionMemory::current());
        self::assertSame(0, $memory->generation());

        $memory->forget(new LastDecisionStore);

        self::assertSame(1, DecisionMemory::current()->generation());

        $app->forgetScopedInstances();

        self::assertNotSame($memory, DecisionMemory::current());
        self::assertSame(0, DecisionMemory::current()->generation());
    }

    /**
     * Forgetting moves the generation on by one each time and clears the last
     * decision, its provenance and the session it was recorded in.
     *
     * @return void
     */
    public function testForgettingMovesTheGenerationOnAndClearsTheLastDecision(): void
    {
        $memory = DecisionMemory::current();
        $store  = new LastDecisionStore;

        $store->put(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT), DecisionProvenance::of(null), 'session-1');

        $memory->forget($store);

        self::assertSame(1, $memory->generation());
        self::assertNull($store->get());
        self::assertNull($store->provenance());
        self::assertTrue($store->wasRecordedIn(null));

        $memory->forget($store);

        self::assertSame(2, $memory->generation());
    }

    /**
     * Forgetting drops the tenant the request resolved, so the next read asks
     * the resolver again, while a scope put in place with `within()` stays
     * until it ends.
     *
     * @return void
     */
    public function testForgettingDropsTheRequestsTenantButKeepsAScopeInPlace(): void
    {
        $first    = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'A']);
        $second   = StubTenant::query()->create(['id' => 'tenant-b', 'name' => 'B']);
        $user     = StubIdentity::create(['id' => 'user-1']);
        $resolver = new ChangingSubjectResolver(new Subject($user, $user, $first));

        $this->container()->instance(SubjectResolver::class, $resolver);
        $this->container()->forgetInstance(ResolvedTenant::class);

        self::assertSame('tenant-a', self::tenantId());

        $resolver->subject = new Subject($user, $user, $second);

        self::assertSame('tenant-a', self::tenantId());

        TenantScope::within($first, 'admin', static function (): void {
            DecisionMemory::current()->forget(new LastDecisionStore);

            self::assertSame('tenant-a', self::tenantId());
            self::assertSame('admin', TenantScope::currentApplication());
        });

        self::assertSame('tenant-b', self::tenantId());

        $resolver->subject = new Subject($user, $user, $first);

        DecisionMemory::current()->forget(new LastDecisionStore);

        self::assertSame('tenant-a', self::tenantId());
    }

    /**
     * Forgetting empties the resolution memo, so what was resolved is read
     * again, from the persistent store while it holds, which is left as it is:
     * no entry written or dropped and no version key bumped.
     *
     * @return void
     */
    public function testForgettingEmptiesTheMemoAndLeavesTheStore(): void
    {
        $array = new ArrayStore;
        $cache = new ResolutionCache(new Repository($array));

        $this->container()->instance(ResolutionCache::class, $cache);

        $this->permissions($cache);
        $this->permissions($cache);

        $held = $array->all();

        self::assertSame(1, $this->resolutions);

        DecisionMemory::current()->forget(new LastDecisionStore);

        self::assertSame($held, $array->all());

        $array->flush();

        $this->permissions($cache);

        self::assertSame(2, $this->resolutions);
    }

    /**
     * Forgetting inside a batch empties the memo in every scope, the entries
     * set aside for a scope left included, so both scopes the batch read in are
     * resolved again.
     *
     * @return void
     */
    public function testForgettingInsideABatchEmptiesEveryScope(): void
    {
        $tenant = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'A']);
        $cache  = new ResolutionCache;

        $this->container()->instance(ResolutionCache::class, $cache);

        $cache->batch(function () use ($cache, $tenant): void {
            $read = function () use ($cache, $tenant): void {
                $this->permissions($cache);

                TenantScope::within($tenant, null, fn (): array => $this->permissions($cache));
            };

            $read();
            $read();

            self::assertSame(2, $this->resolutions);

            DecisionMemory::current()->forget(new LastDecisionStore);

            $read();
        });

        self::assertSame(4, $this->resolutions);
    }

    /**
     * Forgetting in a callback run aside leaves nothing to put back: the
     * entries set aside as it started are dropped with the rest.
     *
     * @return void
     */
    public function testForgettingAsideLeavesNothingToPutBack(): void
    {
        $cache = new ResolutionCache;

        $this->container()->instance(ResolutionCache::class, $cache);

        $this->permissions($cache);

        $cache->batch(static fn () => DecisionMemory::current()->forget(new LastDecisionStore), true);

        $this->permissions($cache);

        self::assertSame(2, $this->resolutions);
    }

    /**
     * With no resolution cache bound, as in an application the package does not
     * manage, forgetting clears the last decision and moves the generation on,
     * and builds no cache.
     *
     * @return void
     */
    public function testWithNoResolutionCacheBoundNothingIsBuilt(): void
    {
        $store = new LastDecisionStore;
        $app   = $this->container();

        $app->offsetUnset(ResolutionCache::class);

        $store->put(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT), DecisionProvenance::of(null));

        DecisionMemory::current()->forget($store);

        self::assertNull($store->get());
        self::assertNull($store->provenance());
        self::assertSame(1, DecisionMemory::current()->generation());
        self::assertFalse($app->bound(ResolutionCache::class));
    }

    /**
     * With no package state held, as in a container the package was never
     * registered in, forgetting refuses nothing and still empties the memo.
     *
     * @return void
     */
    public function testWithNoPackageStateTheMemoIsStillEmptied(): void
    {
        $array = new ArrayStore;
        $cache = new ResolutionCache(new Repository($array));
        $store = new LastDecisionStore;

        $this->container()->instance(ResolutionCache::class, $cache);
        $this->permissions($cache);

        $store->put(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT), DecisionProvenance::of(null));

        $this->container()->forgetInstance(PackageState::class);

        DecisionMemory::current()->forget($store);

        self::assertNull($store->get());
        self::assertSame(1, DecisionMemory::current()->generation());

        $array->flush();

        $this->permissions($cache);

        self::assertSame(2, $this->resolutions);
    }

    /**
     * Forgetting never refuses: while the package refuses, a resolution cache
     * the request has not built is not built, even when its own settings cannot
     * be read, and one already built is left as it is.
     *
     * @return void
     */
    public function testWhileThePackageRefusesTheCacheIsLeftAsItIs(): void
    {
        $cache = new ResolutionCache;
        $store = new LastDecisionStore;
        $app   = $this->container();

        $app->instance(ResolutionCache::class, $cache);
        $this->permissions($cache);

        $this->refuseThePackage();

        $store->put(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT), DecisionProvenance::of(null));

        DecisionMemory::current()->forget($store);

        self::assertNull($store->get());

        $this->permissions($cache);

        self::assertSame(1, $this->resolutions);

        $app->make('config')->set('authorization.cache.ttl', 'soon');
        $app->forgetInstance(ResolutionCache::class);

        DecisionMemory::current()->forget($store);

        self::assertSame(2, DecisionMemory::current()->generation());
    }

    /**
     * Return the id of the tenant checks are decided in now, or null for the
     * platform.
     *
     * @return string|null
     */
    private static function tenantId(): ?string
    {
        $tenant = TenantScope::currentTenant();

        return $tenant === null ? null : $tenant[1];
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
