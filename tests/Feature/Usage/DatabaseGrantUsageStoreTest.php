<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Usage\CoveragePeriod;
use SineMacula\Laravel\Authorization\Usage\DatabaseGrantUsageStore;
use SineMacula\Laravel\Authorization\Usage\UsageBatch;
use Tests\TestCase;

/**
 * Feature tests for the package's grant usage store: monotonic, idempotent
 * writes of each route's last observed bucket, safe under duplicate and
 * out-of-order delivery, a regrant's observation replacing the old grant's and
 * never the reverse, and coverage periods that open and extend.
 *
 * @phpstan-import-type Observation from \SineMacula\Laravel\Authorization\Usage\UsageBatch
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseGrantUsageStore::class)]
final class DatabaseGrantUsageStoreTest extends TestCase
{
    /** @var int A bucket's start, 2026-05-09 10:00:00 UTC. */
    private const int TEN = 1778320800;

    /**
     * An observation is kept with its stored grant, and read back by its key; a
     * key never observed reads nothing.
     *
     * @return void
     */
    public function testAnObservationIsKeptAndReadBack(): void
    {
        $store = new DatabaseGrantUsageStore;

        $store->record(new UsageBatch([self::observation('a', self::TEN - 600, self::TEN)], self::TEN + 5));

        $found = $store->lastObserved(['a', 'b']);

        self::assertSame(['a'], \array_keys($found));
        self::assertSame(self::TEN, $found['a']->lastObservedAt->getTimestamp());
        self::assertSame(self::TEN - 600, $found['a']->grantCreatedAt?->getTimestamp());

        $row = (array) DB::table('authorization_grant_usage')->sole();

        $columns = ['grant_source', 'grant_id', 'authorizable_type', 'authorizable_id', 'tenant_type', 'tenant_id', 'application'];

        self::assertSame(['role', 'role-1', 'user', 'ann', 'tenant', 't1', 'web'], \array_map(static fn (string $column): mixed => $row[$column], $columns));
    }

    /**
     * The last observed bucket never moves backwards: a batch delivered twice,
     * or an older one delivered after a newer, changes nothing; a newer one
     * moves it on.
     *
     * @return void
     */
    public function testWritesAreMonotonicAndIdempotent(): void
    {
        $store = new DatabaseGrantUsageStore;
        $newer = new UsageBatch([self::observation('a', null, self::TEN + 3600)], self::TEN + 3700);
        $older = new UsageBatch([self::observation('a', null, self::TEN)], self::TEN + 100);

        $store->record($newer);
        $store->record($older);
        $store->record($newer);

        self::assertSame(self::TEN + 3600, $store->lastObserved(['a'])['a']->lastObservedAt->getTimestamp());

        $store->record(new UsageBatch([self::observation('a', null, self::TEN + 7200)], self::TEN + 7300));

        self::assertSame(self::TEN + 7200, $store->lastObserved(['a'])['a']->lastObservedAt->getTimestamp());
        self::assertSame(1, DB::table('authorization_grant_usage')->count());
    }

    /**
     * An observation of a grant created later replaces the old grant's, even in
     * an earlier bucket; one of a grant created earlier, delivered late, never
     * replaces a regrant's; within one batch the newest is kept.
     *
     * @return void
     */
    public function testARegrantsObservationWinsOverTheOldGrants(): void
    {
        $store = new DatabaseGrantUsageStore;

        $store->record(new UsageBatch([self::observation('a', self::TEN - 7200, self::TEN + 3600)], self::TEN + 3700));
        $store->record(new UsageBatch([self::observation('a', self::TEN - 60, self::TEN)], self::TEN + 100));

        $kept = $store->lastObserved(['a'])['a'];

        self::assertSame(self::TEN - 60, $kept->grantCreatedAt?->getTimestamp());
        self::assertSame(self::TEN, $kept->lastObservedAt->getTimestamp());

        $store->record(new UsageBatch([self::observation('a', self::TEN - 7200, self::TEN + 7200)], self::TEN + 7300));

        self::assertSame(self::TEN - 60, $store->lastObserved(['a'])['a']->grantCreatedAt?->getTimestamp());

        $batch = [self::observation('b', null, self::TEN + 3600), self::observation('b', null, self::TEN), self::observation('b', self::TEN - 5, self::TEN)];

        $store->record(new UsageBatch($batch, self::TEN + 3700));

        $b = $store->lastObserved(['b'])['b'];

        self::assertSame([self::TEN - 5, self::TEN], [$b->grantCreatedAt?->getTimestamp(), $b->lastObservedAt->getTimestamp()]);
    }

    /**
     * A grant that records no creation is replaced by one that does, never the
     * reverse.
     *
     * @return void
     */
    public function testAGrantWithNoCreationCountsAsTheOldest(): void
    {
        $store = new DatabaseGrantUsageStore;

        $store->record(new UsageBatch([self::observation('a', self::TEN - 60, self::TEN)], self::TEN));
        $store->record(new UsageBatch([self::observation('a', null, self::TEN + 3600)], self::TEN + 3600));

        self::assertSame(self::TEN, $store->lastObserved(['a'])['a']->lastObservedAt->getTimestamp());

        $store->record(new UsageBatch([self::observation('c', null, self::TEN)], self::TEN));
        $store->record(new UsageBatch([self::observation('c', self::TEN - 60, self::TEN)], self::TEN));

        self::assertSame(self::TEN - 60, $store->lastObserved(['c'])['c']->grantCreatedAt?->getTimestamp());
    }

    /**
     * Each flush extends the current coverage period while the gap since it
     * ended is at most two intervals, and opens a new one past that; a flush at
     * or before a period's end leaves it.
     *
     * @return void
     */
    public function testCoverageOpensAndExtends(): void
    {
        config(['authorization.usage.interval' => 3600]);

        $store = new DatabaseGrantUsageStore;

        $store->record(new UsageBatch([], self::TEN));
        $store->record(new UsageBatch([], self::TEN + 7200));
        $store->record(new UsageBatch([], self::TEN + 3600));

        self::assertSame([[self::TEN, self::TEN + 7200]], self::periods($store->coverage(self::at(self::TEN), self::at(self::TEN + 99999))));

        $store->record(new UsageBatch([], self::TEN + 7200 + 7201));

        $periods = self::periods($store->coverage(self::at(self::TEN), self::at(self::TEN + 99999)));

        self::assertSame([[self::TEN, self::TEN + 7200], [self::TEN + 14401, self::TEN + 14401]], $periods);
        self::assertSame([[self::TEN + 14401, self::TEN + 14401]], self::periods($store->coverage(self::at(self::TEN + 7201), self::at(self::TEN + 99999))));
        self::assertSame([], self::periods($store->coverage(self::at(self::TEN - 100), self::at(self::TEN))));
    }

    /**
     * Return an observation of the route, its stored grant fixed, created and
     * observed as given.
     *
     * @param  string  $key
     * @param  int|null  $created
     * @param  int  $observed
     * @return Observation
     */
    private static function observation(string $key, ?int $created, int $observed): array
    {
        return [
            'grant_key'         => $key,
            'grant_source'      => 'role',
            'grant_id'          => 'role-1',
            'authorizable_type' => 'user',
            'authorizable_id'   => 'ann',
            'tenant_type'       => 'tenant',
            'tenant_id'         => 't1',
            'application'       => 'web',
            'grant_created_at'  => $created,
            'last_observed_at'  => $observed,
        ];
    }

    /**
     * Return the instant at the timestamp, in UTC.
     *
     * @param  int  $timestamp
     * @return \Carbon\CarbonImmutable
     */
    private static function at(int $timestamp): CarbonImmutable
    {
        return CarbonImmutable::createFromTimestampUTC($timestamp);
    }

    /**
     * Return each period as its start and end timestamps.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Usage\CoveragePeriod>  $periods
     * @return list<array{int, int}>
     */
    private static function periods(array $periods): array
    {
        return \array_map(static fn (CoveragePeriod $period): array => [$period->from->getTimestamp(), $period->until->getTimestamp()], $periods);
    }
}
