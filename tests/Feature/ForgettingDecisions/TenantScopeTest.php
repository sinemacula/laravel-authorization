<?php

declare(strict_types = 1);

namespace Tests\Feature\ForgettingDecisions;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\DecisionMemory;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Feature\Stubs\ChangingSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for the tenant scope holding the tenant in place while the
 * decisions of the request are forgotten (N112): `pinned()` keeps it until the
 * callback returns, and the request's tenant, and what the resolution cache
 * took in the held one, are read afresh afterwards.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantScope::class)]
final class TenantScopeTest extends TestCase
{
    /** @var int How many times a resolution ran. */
    private int $resolutions = 0;

    /**
     * The tenant in place is held while the callback runs, though the request
     * moves to another and the decisions are forgotten, and the request's is
     * read afresh once it returns.
     *
     * @return void
     */
    public function testTheTenantInPlaceIsHeldUntilTheCallbackReturns(): void
    {
        $resolver = $this->resolveIn('tenant-a');

        $inside = TenantScope::pinned(function () use ($resolver): ?string {
            $this->moveTo($resolver, 'tenant-b');

            return self::tenantId();
        });

        self::assertSame('tenant-a', $inside);
        self::assertSame('tenant-b', self::tenantId());
    }

    /**
     * Inside a `within()`, the callback runs as it is: the scope `within()` put
     * in place is the one held, and it stays in place once the callback
     * returns, though the decisions were forgotten in it.
     *
     * @return void
     */
    public function testInsideAWithinTheCallbackRunsAsItIs(): void
    {
        $resolver = $this->resolveIn('tenant-a');
        $other    = StubTenant::query()->create(['id' => 'tenant-c', 'name' => 'C']);

        $after = TenantScope::within($other, null, function () use ($resolver): ?string {
            TenantScope::pinned(fn () => $this->moveTo($resolver, 'tenant-b'));

            return self::tenantId();
        });

        self::assertSame('tenant-c', $after);
        self::assertSame('tenant-b', self::tenantId());
    }

    /**
     * With nothing forgotten, what the resolution cache took is kept once the
     * callback returns, and the tenant is held no longer: forgetting the
     * decisions afterwards moves the request to its new tenant.
     *
     * @return void
     */
    public function testWithNothingForgottenTheMemoIsKeptAndNothingHeldAfter(): void
    {
        $resolver = $this->resolveIn('tenant-a');
        $cache    = $this->cache();

        $this->permissions($cache);

        TenantScope::pinned(fn (): array => $this->permissions($cache));

        $this->permissions($cache);

        self::assertSame(1, $this->resolutions);

        $this->moveTo($resolver, 'tenant-b');

        self::assertSame('tenant-b', self::tenantId());
    }

    /**
     * Once the callback returns after the decisions were forgotten, what the
     * resolution cache took in the held tenant is read again, and the request's
     * tenant is read afresh even when a `within()` run in the callback put the
     * held one back.
     *
     * @return void
     */
    public function testAfterAForgetTheHeldTenantsMemoAndHolderAreDropped(): void
    {
        $resolver = $this->resolveIn('tenant-a');
        $other    = StubTenant::query()->create(['id' => 'tenant-c', 'name' => 'C']);
        $cache    = $this->cache();

        TenantScope::pinned(function () use ($resolver, $other, $cache): void {
            $this->moveTo($resolver, 'tenant-b');

            TenantScope::within($other, null, static fn (): null => null);

            $this->permissions($cache);
        });

        $this->permissions($cache);

        self::assertSame(2, $this->resolutions);
        self::assertSame('tenant-b', self::tenantId());
    }

    /**
     * With no resolution cache bound, the callback returning after the
     * decisions were forgotten reads the request's tenant afresh all the same.
     *
     * @return void
     */
    public function testWithNoResolutionCacheTheTenantIsStillReadAfresh(): void
    {
        $resolver = $this->resolveIn('tenant-a');

        $this->container()->offsetUnset(ResolutionCache::class);

        TenantScope::pinned(fn () => $this->moveTo($resolver, 'tenant-b'));

        self::assertSame('tenant-b', self::tenantId());
        self::assertFalse($this->container()->bound(ResolutionCache::class));
    }

    /**
     * Resolve the request's subject in a new tenant of the given id, with the
     * tenant read afresh.
     *
     * @param  string  $tenant
     * @return \Tests\Feature\Stubs\ChangingSubjectResolver
     */
    private function resolveIn(string $tenant): ChangingSubjectResolver
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $resolver = new ChangingSubjectResolver(new Subject($user, $user, StubTenant::query()->create(['id' => $tenant, 'name' => $tenant])));

        $this->container()->instance(SubjectResolver::class, $resolver);
        $this->container()->forgetInstance(ResolvedTenant::class);

        self::assertSame($tenant, self::tenantId());

        return $resolver;
    }

    /**
     * Move the request's subject into a new tenant of the given id and forget
     * the decisions.
     *
     * @param  \Tests\Feature\Stubs\ChangingSubjectResolver  $resolver
     * @param  string  $tenant
     * @return void
     */
    private function moveTo(ChangingSubjectResolver $resolver, string $tenant): void
    {
        $user = $resolver->subject->subject ?? new \stdClass;

        $resolver->subject = new Subject($user, $user, StubTenant::query()->firstOrCreate(['id' => $tenant], ['name' => $tenant]));

        DecisionMemory::current()->forget(new LastDecisionStore);
    }

    /**
     * Bind a resolution cache keeping its memo only, and return it.
     *
     * @return \SineMacula\Laravel\Authorization\Cache\ResolutionCache
     */
    private function cache(): ResolutionCache
    {
        $cache = new ResolutionCache;

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
}
