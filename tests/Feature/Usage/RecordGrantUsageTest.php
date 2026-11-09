<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;
use SineMacula\Laravel\Authorization\Usage\DatabaseGrantUsageStore;
use SineMacula\Laravel\Authorization\Usage\RecordGrantUsage;
use SineMacula\Laravel\Authorization\Usage\UsageBatch;
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
        $batch = new UsageBatch([], 3600);
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
}
