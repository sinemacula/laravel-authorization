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
 * what is noted sent as one queued job when flushed or once a batch's worth is
 * held, and a queue that refuses the job written to the log and never thrown.
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
            $observed = \array_map($fields, $job->batch->observations);
            $ten      = Carbon::parse('2026-11-09 10:00:00')->getTimestamp();

            return $observed === [['a', 100, $ten], ['b', 100, $ten], ['a', 99, $ten], ['a', 100, $ten + 3600]] && $job->batch->at === $ten + 3600;
        });

        self::assertSame(0, $recorder->pending());
    }

    /**
     * Once a worker holds a batch's worth it flushes them at once, so it never
     * holds more; the routes it remembers are forgotten past ten batches'
     * worth, so a long-running worker stays bounded.
     *
     * @return void
     */
    public function testALongRunningWorkerStaysBounded(): void
    {
        Bus::fake([RecordGrantUsage::class]);
        config(['authorization.usage.batch' => 2]);
        Carbon::setTestNow('2026-11-09 10:15:00');

        $recorder = $this->recorder();

        $recorder->observe([self::route('a'), self::route('b'), self::route('c')]);

        self::assertSame(0, $recorder->pending());
        Bus::assertDispatchedTimes(RecordGrantUsage::class, 1);

        for ($index = 0; $index < 20; $index++) {
            $recorder->observe([self::route('r' . $index)]);

            self::assertLessThan(2, $recorder->pending());
        }

        $recorder->observe([self::route('a')]);

        self::assertSame(1, $recorder->pending());
    }

    /**
     * A queue that refuses the job is written to the log channel, never thrown,
     * and what was noted is dropped; the job names the configured connection
     * and queue.
     *
     * @return void
     */
    public function testAQueueThatRefusesTheJobNeverThrows(): void
    {
        $logger = new RecordingLogger;

        $this->app?->instance('log', $logger);

        $bus = \Mockery::mock(Dispatcher::class);

        $bus->shouldReceive('dispatch')->once()->andThrow(new \RuntimeException('queue down'));

        $recorder = new GrantUsageRecorder($bus);

        $recorder->observe([self::route('a')]);
        $recorder->flush();

        self::assertSame(0, $recorder->pending());
        self::assertSame(['Authorization: grant usage could not be sent to be recorded — queue down'], $logger->messages());
        self::assertSame(1, $logger->records[0]['context']['observations'] ?? null);

        config(['authorization.usage.connection' => 'usage-connection', 'authorization.usage.queue' => 'usage']);

        $job = new RecordGrantUsage(new UsageBatch([], 0));

        self::assertSame(['usage-connection', 'usage'], [$job->connection, $job->queue]);
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
