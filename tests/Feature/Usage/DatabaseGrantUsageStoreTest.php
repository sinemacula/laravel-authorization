<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Usage\CoveragePeriod;
use SineMacula\Laravel\Authorization\Usage\DatabaseGrantUsageStore;
use SineMacula\Laravel\Authorization\Usage\UsageBatch;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\TestCase;

/**
 * Feature tests for the package's grant usage store: monotonic, idempotent
 * writes of each route's last observed bucket, safe under duplicate and
 * out-of-order delivery and a concurrent insert, written in the order of their
 * keys, a regrant's observation replacing the old grant's and never the
 * reverse; a write that deadlocks tried again and one that keeps failing never
 * extending the coverage; and coverage periods that open, extend and are cut
 * back for observations dropped.
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
    use UsesAnAuthorizationConnection;

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

        $store->record(UsageBatch::of([self::observation('a', self::TEN - 600, self::TEN)], self::TEN + 5));

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
        $newer = UsageBatch::of([self::observation('a', null, self::TEN + 3600)], self::TEN + 3700);
        $older = UsageBatch::of([self::observation('a', null, self::TEN)], self::TEN + 100);

        $store->record($newer);
        $store->record($older);
        $store->record($newer);

        self::assertSame(self::TEN + 3600, $store->lastObserved(['a'])['a']->lastObservedAt->getTimestamp());

        $store->record(UsageBatch::of([self::observation('a', null, self::TEN + 7200)], self::TEN + 7300));

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

        $store->record(UsageBatch::of([self::observation('a', self::TEN - 7200, self::TEN + 3600)], self::TEN + 3700));
        $store->record(UsageBatch::of([self::observation('a', self::TEN - 60, self::TEN)], self::TEN + 100));

        $kept = $store->lastObserved(['a'])['a'];

        self::assertSame(self::TEN - 60, $kept->grantCreatedAt?->getTimestamp());
        self::assertSame(self::TEN, $kept->lastObservedAt->getTimestamp());

        $store->record(UsageBatch::of([self::observation('a', self::TEN - 7200, self::TEN + 7200)], self::TEN + 7300));

        self::assertSame(self::TEN - 60, $store->lastObserved(['a'])['a']->grantCreatedAt?->getTimestamp());

        $batch = [self::observation('b', null, self::TEN + 3600), self::observation('b', null, self::TEN), self::observation('b', self::TEN - 5, self::TEN)];

        $store->record(UsageBatch::of($batch, self::TEN + 3700));

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

        $store->record(UsageBatch::of([self::observation('a', self::TEN - 60, self::TEN)], self::TEN));
        $store->record(UsageBatch::of([self::observation('a', null, self::TEN + 3600)], self::TEN + 3600));

        self::assertSame(self::TEN, $store->lastObserved(['a'])['a']->lastObservedAt->getTimestamp());

        $store->record(UsageBatch::of([self::observation('c', null, self::TEN)], self::TEN));
        $store->record(UsageBatch::of([self::observation('c', self::TEN - 60, self::TEN)], self::TEN));

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

        $store->record(UsageBatch::of([], self::TEN));
        $store->record(UsageBatch::of([], self::TEN + 7200));
        $store->record(UsageBatch::of([], self::TEN + 3600));

        self::assertSame([[self::TEN, self::TEN + 7200]], self::periods($store->coverage(self::at(self::TEN), self::at(self::TEN + 99999))));

        $store->record(UsageBatch::of([], self::TEN + 7200 + 7201));

        $periods = self::periods($store->coverage(self::at(self::TEN), self::at(self::TEN + 99999)));

        self::assertSame([[self::TEN, self::TEN + 7200], [self::TEN + 14401, self::TEN + 14401]], $periods);
        self::assertSame([[self::TEN + 14401, self::TEN + 14401]], self::periods($store->coverage(self::at(self::TEN + 7201), self::at(self::TEN + 99999))));
        self::assertSame([], self::periods($store->coverage(self::at(self::TEN - 100), self::at(self::TEN))));
    }

    /**
     * Within one batch the newest observation of a route never seen is kept: of
     * the same grant, the later bucket whichever comes first; of grants created
     * apart, the later creation whatever its bucket.
     *
     * @return void
     */
    public function testTheNewestOfABatchIsKeptForANewRoute(): void
    {
        $store = new DatabaseGrantUsageStore;

        $store->record(UsageBatch::of([self::observation('d', null, self::TEN + 3600), self::observation('d', null, self::TEN)], self::TEN + 3700));
        $store->record(UsageBatch::of([self::observation('e', self::TEN - 5, self::TEN), self::observation('e', self::TEN - 60, self::TEN + 3600)], self::TEN + 3700));

        $kept = $store->lastObserved(['d', 'e']);

        self::assertSame([null, self::TEN + 3600], [$kept['d']->grantCreatedAt, $kept['d']->lastObservedAt->getTimestamp()]);
        self::assertSame([self::TEN - 5, self::TEN], [$kept['e']->grantCreatedAt?->getTimestamp(), $kept['e']->lastObservedAt->getTimestamp()]);
    }

    /**
     * The routes are written in the order of their keys, each missing row
     * inserted before any is rewritten, and an older observation leaves a newer
     * row unrewritten.
     *
     * @return void
     */
    public function testRoutesAreWrittenInTheOrderOfTheirKeys(): void
    {
        $store = new DatabaseGrantUsageStore;

        $store->record(UsageBatch::of([self::observation('b', null, self::TEN + 3600)], self::TEN + 3700));

        $writes = self::writesDuring(static function () use ($store): void {
            $observations = [self::observation('c', null, self::TEN), self::observation('b', null, self::TEN), self::observation('a', null, self::TEN)];

            $store->record(UsageBatch::of($observations, self::TEN + 3700));
        });

        self::assertSame([['insert', ['a', 'c']]], $writes);
        self::assertSame(3, DB::table('authorization_grant_usage')->count());
    }

    /**
     * A route a concurrent writer inserted between the read and the insert is
     * rewritten when the observation is newer than what it wrote, and kept when
     * it is not, never twice.
     *
     * @return void
     */
    public function testARacedInsertKeepsTheNewer(): void
    {
        $store = new DatabaseGrantUsageStore;

        self::raceWith(self::observation('a', null, self::TEN));
        $store->record(UsageBatch::of([self::observation('a', null, self::TEN + 3600)], self::TEN + 3700));

        self::assertSame(self::TEN + 3600, $store->lastObserved(['a'])['a']->lastObservedAt->getTimestamp());

        self::raceWith(self::observation('b', null, self::TEN + 7200));
        $store->record(UsageBatch::of([self::observation('b', null, self::TEN)], self::TEN + 7300));

        self::assertSame(self::TEN + 7200, $store->lastObserved(['b'])['b']->lastObservedAt->getTimestamp());
        self::assertSame(2, DB::table('authorization_grant_usage')->count());
    }

    /**
     * A transaction that deadlocks or waits too long for a lock is tried again,
     * three times in all; one that still fails throws, and the coverage is not
     * extended.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConcurrencyFailureIsTriedAgainAndNeverExtendsCoverage(): void
    {
        $this->useAnAuthorizationConnection();

        $store = new DatabaseGrantUsageStore;

        self::assertSame(2, self::failingInserts(1, static function () use ($store): void {
            $store->record(UsageBatch::of([self::observation('a', null, self::TEN)], self::TEN + 100));
        }));
        self::assertSame(1, self::authorizationConnection()->table('authorization_grant_usage')->count());
        self::assertSame(1, self::authorizationConnection()->table('authorization_usage_coverage')->count());

        try {
            self::failingInserts(3, static function () use ($store): void {
                $store->record(UsageBatch::of([self::observation('b', null, self::TEN + 3600)], self::TEN + 3700));
            });
            self::fail('A write that kept failing was recorded.');
        } catch (\RuntimeException $exception) {
            self::assertStringContainsString('Deadlock found when trying to get lock', $exception->getMessage());
        }

        self::assertSame([[self::TEN + 100, self::TEN + 100]], self::periods($store->coverage(self::at(self::TEN), self::at(self::TEN + 99999))));
        self::assertSame(['a'], \array_keys($store->lastObserved(['a', 'b'])));
    }

    /**
     * A batch that names observations dropped before it cuts the coverage back
     * to two intervals and a second before the earliest bucket dropped, ending
     * a period that started before the cut there, starting one that ends after
     * the batch at the batch, splitting one that spans both and removing one
     * between them, then opens a new period when none reaches the batch.
     *
     * @return void
     */
    public function testALossCutsTheCoverageBack(): void
    {
        config(['authorization.usage.interval' => 3600]);

        $store = new DatabaseGrantUsageStore;
        $cut   = self::TEN + 30000 - 7201;

        self::cover([[self::TEN, self::TEN + 50000]]);
        $store->record(UsageBatch::of([], self::TEN + 40000, self::TEN + 30000));

        self::assertSame([[self::TEN, $cut], [self::TEN + 40000, self::TEN + 50000]], self::covered($store));

        self::cover([[self::TEN, self::TEN + 25000], [self::TEN + 26000, self::TEN + 35000], [self::TEN + 36000, self::TEN + 45000]]);
        $store->record(UsageBatch::of([], self::TEN + 40000, self::TEN + 30000));

        self::assertSame([[self::TEN, $cut], [self::TEN + 40000, self::TEN + 45000]], self::covered($store));

        self::cover([[self::TEN, self::TEN + 29000]]);
        $store->record(UsageBatch::of([], self::TEN + 31000, self::TEN + 30000));

        self::assertSame([[self::TEN, $cut], [self::TEN + 31000, self::TEN + 31000]], self::covered($store));
    }

    /**
     * Replace the coverage with the periods, each its start and end.
     *
     * @param  list<array{int, int}>  $periods
     * @return void
     */
    private static function cover(array $periods): void
    {
        DB::table('authorization_usage_coverage')->delete();

        foreach ($periods as [$from, $until]) {
            DB::table('authorization_usage_coverage')->insert([
                'covered_from'  => self::at($from)->format('Y-m-d H:i:s'),
                'covered_until' => self::at($until)->format('Y-m-d H:i:s'),
            ]);
        }
    }

    /**
     * Return every period the store keeps, each its start and end.
     *
     * @param  \SineMacula\Laravel\Authorization\Usage\DatabaseGrantUsageStore  $store
     * @return list<array{int, int}>
     */
    private static function covered(DatabaseGrantUsageStore $store): array
    {
        return self::periods($store->coverage(self::at(0), self::at(self::TEN * 2)));
    }

    /**
     * Have a concurrent writer insert the observation's row as soon as the next
     * write reads the usage table, once.
     *
     * @param  Observation  $observation
     * @return void
     */
    private static function raceWith(array $observation): void
    {
        $isRaced = false;

        DB::listen(static function (QueryExecuted $query) use (&$isRaced, $observation): void {
            if ($isRaced || !\str_starts_with($query->sql, 'select') || !\str_contains($query->sql, 'authorization_grant_usage')) {
                return;
            }

            $isRaced = true;

            DB::table('authorization_grant_usage')->insert([
                ...\array_diff_key($observation, ['grant_created_at' => true, 'last_observed_at' => true]),
                'grant_created_at' => null,
                'last_observed_at' => self::at($observation['last_observed_at'])->format('Y-m-d H:i:s'),
            ]);
        });
    }

    /**
     * Run the call with the first inserts into the usage table on the package's
     * own connection failing as a deadlock does, and return how many inserts it
     * tried.
     *
     * @param  int  $failures
     * @param  \Closure(): void  $call
     * @return int
     */
    private static function failingInserts(int $failures, \Closure $call): int
    {
        $tried = 0;

        DB::listen(static function (QueryExecuted $query) use (&$tried, $failures): void {
            if ($query->connectionName !== 'authorization' || !\str_starts_with($query->sql, 'insert') || !\str_contains($query->sql, 'authorization_grant_usage')) {
                return;
            }

            if (++$tried <= $failures) {
                throw new \RuntimeException('Deadlock found when trying to get lock; try restarting transaction');
            }
        });

        try {
            $call();
        } finally {
            Event::forget(QueryExecuted::class);
        }

        return $tried;
    }

    /**
     * Return each write the call made to the usage table, as its statement and
     * the route keys it names, in order.
     *
     * @param  \Closure(): void  $call
     * @return list<array{string, list<string>}>
     */
    private static function writesDuring(\Closure $call): array
    {
        $writes = [];

        DB::listen(static function (QueryExecuted $query) use (&$writes): void {
            if (\str_starts_with($query->sql, 'select') || !\str_contains($query->sql, 'authorization_grant_usage')) {
                return;
            }

            $keys     = \array_values(\array_filter($query->bindings, static fn (mixed $binding): bool => \in_array($binding, ['a', 'b', 'c'], true)));
            $writes[] = [\strtok($query->sql, ' ') ?: '', $keys];
        });

        $call();

        Event::forget(QueryExecuted::class);

        return $writes;
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
