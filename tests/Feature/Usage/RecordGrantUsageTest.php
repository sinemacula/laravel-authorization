<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use Illuminate\Queue\NullQueue;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;
use SineMacula\Laravel\Authorization\Usage\DatabaseGrantUsageStore;
use SineMacula\Laravel\Authorization\Usage\RecordGrantUsage;
use SineMacula\Laravel\Authorization\Usage\UsageBatch;
use SineMacula\Laravel\Authorization\Usage\UsageTracking;
use Tests\Fixtures\Usage\CountingUsageStore;
use Tests\TestCase;

/**
 * Feature tests for the queued job that records a batch of grant usage: it is
 * sent to the configured connection and queue, survives the queue, and hands
 * its batch to the store bound when it runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordGrantUsage::class)]
final class RecordGrantUsageTest extends TestCase
{
    /**
     * The job names the default connection and queue unless others are
     * configured, survives being serialised, and records its batch in the store
     * bound, an application's included.
     *
     * @return void
     */
    public function testTheJobRecordsItsBatchInTheBoundStore(): void
    {
        $batch = UsageBatch::of([], 3600);
        $job   = new RecordGrantUsage($batch);

        self::assertSame([null, null], [$job->connection, $job->queue]);

        config(['authorization.usage.connection' => 'database', 'authorization.usage.queue' => 'usage']);

        $job = \unserialize(\serialize(new RecordGrantUsage($batch)));

        self::assertInstanceOf(RecordGrantUsage::class, $job);
        self::assertSame(['database', 'usage'], [$job->connection, $job->queue]);

        $store = new CountingUsageStore(new DatabaseGrantUsageStore);

        $this->app?->instance(GrantUsageStore::class, $store);
        $this->app?->call([$job, 'handle']);

        self::assertCount(1, $store->batches);
        self::assertSame(3600, $store->batches[0]->at);
    }

    /**
     * A job of the default batch's worth of observations, each of a grant of
     * its own with every column as long as a UUID keyed grant makes it, is well
     * under the 256 KB a queue such as SQS allows a job.
     *
     * @return void
     */
    public function testAFullJobIsWellUnderAQueuesLimit(): void
    {
        $observations = [];

        for ($index = 0; $index < UsageTracking::BATCH; $index++) {
            $observations[] = [
                'grant_key'         => \hash('sha256', (string) $index),
                'grant_source'      => 'permission',
                'grant_id'          => \sprintf('%08x-1234-4abc-9def-%012x', $index, $index),
                'authorizable_type' => 'App\Models\Organisation\Member',
                'authorizable_id'   => \sprintf('%08x-aaaa-4bbb-8ccc-%012x', $index, $index),
                'tenant_type'       => 'App\Models\Organisation\Workspace',
                'tenant_id'         => \sprintf('%08x-dddd-4eee-8fff-%012x', $index, $index),
                'application'       => 'customer-portal',
                'grant_created_at'  => 1762000000 + $index,
                'last_observed_at'  => 1762678800,
            ];
        }

        $queue = new class extends NullQueue {
            /**
             * Return the payload the queue would push for the job.
             *
             * @param  object  $job
             * @return string
             */
            public function payloadOf(object $job): string
            {
                return $this->createPayload($job, 'default');
            }
        };

        self::assertNotNull($this->app);

        $queue->setContainer($this->app);

        $payload = $queue->payloadOf(new RecordGrantUsage(UsageBatch::of($observations, 1762680000)));

        self::assertSame(250, UsageTracking::BATCH);
        self::assertLessThan(128 * 1024, \strlen($payload));
    }
}
