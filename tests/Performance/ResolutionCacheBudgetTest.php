<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository as CacheRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use Tests\Concerns\MeasuresTime;
use Tests\TestCase;

/**
 * Performance budget for `ResolutionCache` memo-tier reads.
 *
 * The in-memory memo sits on every repeated `can()` and `hasPermission()` call
 * within a request. A regression in the memo-tier lookup compounds linearly
 * with check count, so the suite codifies a loose wall-clock bound on 10,000
 * memo-hit lookups — catches a 10× regression, tolerates CI variance.
 *
 * A second subject verifies that an entry bounded by a grant's expiry is still
 * written to the persistent tier and read back — a correctness-adjacent budget
 * that guards the self-invalidation path.
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
    use MeasuresTime;

    /** @var string Permission name shared by the memo-hit and round-trip subjects. */
    private const string PERMISSION = 'posts:create';

    /** @var string Companion permission used alongside `PERMISSION` in the round-trip subject. */
    private const string PERMISSION_READ = 'posts:read';

    /**
     * A primed memo-tier read must stay cheap. Observed about 0.5μs per call on
     * the reference machine (5ms for the loop), so the budget is 0.1s: about
     * 20× the reference figure, which a runaway `in_array` or an accidental
     * store lookup per read would exceed. The budget is enforced outside
     * coverage runs.
     *
     * @return void
     */
    public function testMemoTierReadOverheadStaysBounded(): void
    {
        $cache     = new ResolutionCache(store: null, prefix: 'budget');
        $principal = self::principal();
        $resolver  = static fn (): Resolution => new Resolution([self::PERMISSION, self::PERMISSION_READ, 'posts:update']);

        // Prime the memo so the measured calls all hit the memo tier.
        $cache->rememberPermissions($principal, $resolver);

        $start = \microtime(true);

        for ($i = 0; $i < 10000; $i++) {
            $cache->rememberPermissions($principal, $resolver);
        }

        $elapsed = \microtime(true) - $start;

        $this->assertWithinBudget(
            0.1,
            $elapsed,
            "ResolutionCache memo-tier read budget exceeded ({$elapsed}s for 10,000 hits).",
        );
    }

    /**
     * A grant's expiry bounds the persistent-tier entry's lifetime to a second
     * before it, under the configured maximum. A re-read of the same slot from
     * another instance must round-trip the value, proving the bounded write
     * executed rather than being skipped as already lapsed.
     *
     * @return void
     */
    public function testTemporalGrantBoundsPersistentTierTtl(): void
    {
        $arrayStore      = new ArrayStore;
        $cacheRepository = new CacheRepository($arrayStore);

        // A grant expiring in 30 seconds bounds the entry to 29, under the
        // 300-second maximum. A separate cache instance reads through the same
        // store so the memo tier cannot mask a missing persistent-tier write.
        $writer    = new ResolutionCache(store: $cacheRepository, prefix: 'budget');
        $reader    = new ResolutionCache(store: $cacheRepository, prefix: 'budget');
        $principal = self::principal();

        $writer->rememberPermissions(
            $principal,
            static fn (): Resolution => new Resolution([self::PERMISSION, self::PERMISSION_READ], 30),
        );

        $roundTrip = $reader->rememberPermissions(
            $principal,
            static fn (): Resolution => new Resolution(['should-not-be-called']),
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
