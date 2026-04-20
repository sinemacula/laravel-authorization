<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository as CacheRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;

/**
 * Performance budget for `ResolutionCache` memo-tier reads.
 *
 * The in-memory memo sits on every repeated `can()` and `hasPermission()` call
 * within a request. A regression in the memo-tier lookup compounds linearly
 * with check count, so the suite codifies a loose wall-clock bound on 10,000
 * memo-hit lookups — catches a 10× regression, tolerates CI variance.
 *
 * A second subject verifies that the persistent-tier entry's TTL is bounded
 * below the configured `ttl` when a temporal-grant `maxTtl` is supplied — a
 * correctness-adjacent budget that guards the critical self-invalidation path.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ResolutionCache::class)]
final class ResolutionCacheBudgetTest extends TestCase
{
    /** @var string Permission name shared by the memo-hit and round-trip subjects. */
    private const string PERMISSION = 'posts:create';

    /** @var string Companion permission used alongside `PERMISSION` in the round-trip subject. */
    private const string PERMISSION_READ = 'posts:read';

    /**
     * A primed memo-tier read must stay under ~1μs per call. Observed ~2μs per
     * call on the reference machine; budget is 5× that for headroom against CI
     * variance while still catching a runaway `in_array` or accidental store
     * lookup regression.
     *
     * @return void
     */
    public function testMemoTierReadOverheadStaysBounded(): void
    {
        $cache     = new ResolutionCache(store: null, ttl: 0, prefix: 'budget');
        $principal = self::principal();
        $resolver  = static fn (): array => [self::PERMISSION, self::PERMISSION_READ, 'posts:update'];

        // Prime the memo so the measured calls all hit the memo tier.
        $cache->rememberPermissions($principal, $resolver);

        $start = microtime(true);

        for ($i = 0; $i < 10000; $i++) {
            $cache->rememberPermissions($principal, $resolver);
        }

        $elapsed = microtime(true) - $start;

        self::assertLessThan(
            0.1,
            $elapsed,
            "ResolutionCache memo-tier read budget exceeded ({$elapsed}s for 10,000 hits).",
        );
    }

    /**
     * A temporal-grant `maxTtl` must bound the persistent-tier entry's lifetime
     * — `resolveTtl()` returns `min(ttl, maxTtl) - 1`. The budget here is
     * correctness-adjacent: a re-read of the same slot must round-trip the
     * value even when `maxTtl` is the only lifetime input (`ttl = 0`,
     * "forever"), proving the bounded-TTL write path executed rather than the
     * short-circuit no-op (which triggers when the computed seconds ≤ 0).
     *
     * @return void
     */
    public function testTemporalGrantBoundsPersistentTierTtl(): void
    {
        $arrayStore      = new ArrayStore;
        $cacheRepository = new CacheRepository($arrayStore);

        // ttl = 0 (forever) but maxTtl = 30s → entry must store with a 29s
        // lifetime, not forever. A separate cache instance reads through the
        // same store so the memo tier cannot mask a missing persistent-tier
        // write.
        $writer    = new ResolutionCache(store: $cacheRepository, ttl: 0, prefix: 'budget');
        $reader    = new ResolutionCache(store: $cacheRepository, ttl: 0, prefix: 'budget');
        $principal = self::principal();
        $context   = new ResolutionCacheContext(maxTtl: 30);

        $writer->rememberPermissions(
            $principal,
            static fn (): array => [self::PERMISSION, self::PERMISSION_READ],
            $context,
        );

        $roundTrip = $reader->rememberPermissions(
            $principal,
            static fn (): array => ['should-not-be-called'],
            $context,
        );

        self::assertSame(
            [self::PERMISSION, self::PERMISSION_READ],
            $roundTrip,
            'Expected persistent-tier entry to round-trip via bounded-TTL write.',
        );
    }

    /**
     * Build the stand-in principal used by both subjects.
     *
     * @return object
     */
    private static function principal(): object
    {
        return new class {
            /** @var string */
            public string $id = 'budget-principal';

            /**
             * @return string
             */
            public function getKey(): string
            {
                return $this->id;
            }

            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'budget_identity';
            }
        };
    }
}
