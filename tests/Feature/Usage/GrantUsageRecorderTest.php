<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use Illuminate\Contracts\Bus\Dispatcher;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Bus;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Usage\GrantRoute;
use SineMacula\Laravel\Authorization\Usage\GrantUsageRecorder;
use SineMacula\Laravel\Authorization\Usage\RecordGrantUsage;
use SineMacula\Laravel\Authorization\Usage\StoredGrant;
use SineMacula\Laravel\Authorization\Usage\UsageBatch;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\TestCase;

/**
 * Feature tests for the grant usage recorder: each route noted once a bucket
 * per worker, the noted routes forgotten as a bucket begins and past a bound,
 * what is noted sent only when flushed, a batch's worth set aside as a job of
 * its own, the oldest batch dropped past the most held and named by the next
 * job, and a queue that refuses a job written to the log and never thrown.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantUsageRecorder::class)]
final class GrantUsageRecorderTest extends TestCase
{
    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * A route is noted once a bucket, in the bucket it fell in, the routes of
     * another grant creation apart; a new bucket notes it again, and a flush
     * sends what is noted as one job and nothing when nothing is.
     *
     * @return void
     */
    public function testARouteIsNotedOnceABucket(): void
    {
        Bus::fake([RecordGrantUsage::class]);

        $recorder = $this->recorder();

        Carbon::setTestNow('2026-11-09 10:15:00');
        $recorder->observe([self::route('a'), self::route('b'), self::route('a'), self::route('a', 99)]);

        Carbon::setTestNow('2026-11-09 10:59:59');
        $recorder->observe([self::route('a')]);

        self::assertSame(3, $recorder->pending());

        Carbon::setTestNow('2026-11-09 11:00:00');
        $recorder->observe([self::route('a')]);
        $recorder->observe([]);
        $recorder->flush();
        $recorder->flush();

        Bus::assertDispatchedTimes(RecordGrantUsage::class, 1);
        Bus::assertDispatched(RecordGrantUsage::class, static function (RecordGrantUsage $job): bool {
            $fields   = static fn (array $observation): array => [$observation['grant_key'], $observation['grant_created_at'], $observation['last_observed_at']];
            $observed = \array_map($fields, $job->batch->observations());
            $ten      = Carbon::parse('2026-11-09 10:00:00')->getTimestamp();

            return $observed === [['a', 100, $ten], ['b', 100, $ten], ['a', 99, $ten], ['a', 100, $ten + 3600]] && $job->batch->at === $ten + 3600;
        });

        self::assertSame(0, $recorder->pending());
    }

    /**
     * A batch's worth of routes is set aside, never sent from within a check,
     * and each batch set aside is sent as a job of its own when the recorder
     * flushes, so a long-running worker stays bounded and no job outgrows a
     * queue's limit.
     *
     * @return void
     */
    public function testABatchIsSetAsideAndSentOnlyWhenFlushed(): void
    {
        Bus::fake([RecordGrantUsage::class]);
        config(['authorization.usage.batch' => 2]);
        Carbon::setTestNow('2026-11-09 10:15:00');

        $recorder = $this->recorder();

        $recorder->observe([self::route('a'), self::route('b'), self::route('c')]);
        $recorder->observe([self::route('d')]);

        self::assertSame(4, $recorder->pending());
        Bus::assertNothingDispatched();

        $recorder->flush();

        self::assertSame(0, $recorder->pending());
        self::assertSame([['a', 'b', 'c'], ['d']], self::keysSent());
    }

    /**
     * The routes noted are forgotten exactly once ten batches' worth are
     * remembered, so a route noted before then is noted again, and never
     * sooner.
     *
     * @return void
     */
    public function testTheRoutesRememberedAreBoundedAtTenBatches(): void
    {
        Bus::fake([RecordGrantUsage::class]);
        config(['authorization.usage.batch' => 2]);
        Carbon::setTestNow('2026-11-09 10:15:00');

        $recorder = $this->recorder();

        for ($index = 0; $index < 19; $index++) {
            $recorder->observe([self::route('r' . $index)]);
        }

        $recorder->observe([self::route('r0')]);

        self::assertSame(19, $recorder->pending());

        $recorder->observe([self::route('r19')]);
        $recorder->observe([self::route('r0')]);

        self::assertSame(21, $recorder->pending());
    }

    /**
     * Past ten batches set aside the oldest is dropped, and the first job sent
     * names the earliest bucket it was noted in; the jobs after it name none.
     *
     * @return void
     */
    public function testTheOldestBatchIsDroppedPastTheMostHeld(): void
    {
        Bus::fake([RecordGrantUsage::class]);
        config(['authorization.usage.batch' => 1]);

        $recorder = $this->recorder();
        $ten      = Carbon::parse('2026-11-09 10:00:00')->getTimestamp();

        Carbon::setTestNow('2026-11-09 10:15:00');
        $recorder->observe([self::route('r0')]);

        Carbon::setTestNow('2026-11-09 11:15:00');

        for ($index = 1; $index <= 10; $index++) {
            $recorder->observe([self::route('r' . $index)]);
        }

        self::assertSame(10, $recorder->pending());

        $recorder->flush();

        $jobs = self::jobsSent();

        self::assertSame(\array_map(static fn (int $index): array => ['r' . $index], \range(1, 10)), self::keysSent());
        self::assertSame([$ten, null], [$jobs[0]->batch->lostSince, $jobs[1]->batch->lostSince]);
    }

    /**
     * A queue that refuses a job is written to the log channel, never thrown,
     * and the observations it carried are dropped, their routes forgotten so a
     * later use notes them again, and named by the next job sent, one of no
     * observations when nothing else is; the job names the configured
     * connection and queue.
     *
     * @return void
     */
    public function testAQueueThatRefusesTheJobNeverThrows(): void
    {
        $logger = new RecordingLogger;

        $this->app?->instance('log', $logger);

        $sent = [];
        $bus  = \Mockery::mock(Dispatcher::class);

        $bus->shouldReceive('dispatch')->once()->andThrow(new \RuntimeException('queue down'));
        $bus->shouldReceive('dispatch')->once()->andReturnUsing(static function (RecordGrantUsage $job) use (&$sent): int {
            $sent[] = $job;

            return 0;
        });

        $recorder = new GrantUsageRecorder($bus);

        Carbon::setTestNow('2026-11-09 10:15:00');
        $recorder->observe([self::route('a')]);
        $recorder->flush();

        self::assertSame(0, $recorder->pending());
        self::assertSame(['Authorization: grant usage could not be sent to be recorded — queue down'], $logger->messages());
        self::assertSame(1, $logger->records[0]['context']['observations'] ?? null);

        $recorder->observe([self::route('a')]);

        self::assertSame(1, $recorder->pending());

        $recorder->flush();
        $recorder->flush();

        $ten = Carbon::parse('2026-11-09 10:00:00')->getTimestamp();

        self::assertCount(1, $sent);
        self::assertSame([[['a', 0, $ten]], $ten], [$sent[0]->batch->routes, $sent[0]->batch->lostSince]);

        $quiet = new GrantUsageRecorder($bus = \Mockery::mock(Dispatcher::class));

        $bus->shouldReceive('dispatch')->once()->andThrow(new \RuntimeException('queue down'));
        $bus->shouldReceive('dispatch')->once()->andReturnUsing(static function (RecordGrantUsage $job) use (&$sent): int {
            $sent[] = $job;

            return 0;
        });

        $quiet->observe([self::route('a')]);
        $quiet->flush();
        $quiet->flush();

        self::assertSame([[], $ten], [$sent[1]->batch->routes, $sent[1]->batch->lostSince]);

        config(['authorization.usage.connection' => 'usage-connection', 'authorization.usage.queue' => 'usage']);

        $job = new RecordGrantUsage(UsageBatch::of([], 0));

        self::assertSame(['usage-connection', 'usage'], [$job->connection, $job->queue]);
    }

    /**
     * Return the keys of the routes each job sent carries, in the order sent.
     *
     * @return list<list<string>>
     */
    private static function keysSent(): array
    {
        return \array_map(static fn (RecordGrantUsage $job): array => \array_column($job->batch->routes, 0), self::jobsSent());
    }

    /**
     * Return the recording jobs sent, in the order sent.
     *
     * @return list<\SineMacula\Laravel\Authorization\Usage\RecordGrantUsage>
     */
    private static function jobsSent(): array
    {
        $jobs = [];

        foreach (Bus::dispatched(RecordGrantUsage::class) as $job) {
            self::assertInstanceOf(RecordGrantUsage::class, $job);

            $jobs[] = $job;
        }

        return $jobs;
    }

    /**
     * Return a recorder sending through the bound dispatcher.
     *
     * @return \SineMacula\Laravel\Authorization\Usage\GrantUsageRecorder
     */
    private function recorder(): GrantUsageRecorder
    {
        $bus = $this->app?->make(Dispatcher::class);

        self::assertInstanceOf(Dispatcher::class, $bus);

        return new GrantUsageRecorder($bus);
    }

    /**
     * Return a route with the key, through a grant created at the timestamp.
     *
     * @param  string  $key
     * @param  int  $created
     * @return \SineMacula\Laravel\Authorization\Usage\GrantRoute
     */
    private static function route(string $key, int $created = 100): GrantRoute
    {
        return new GrantRoute($key, new StoredGrant(GrantTarget::ROLE, 'role-1', new Reference('user', 'ann'), null, null, null, $created));
    }
}
