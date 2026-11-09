<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Queue\Job;
use Illuminate\Foundation\Application;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Support\Facades\Bus;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Registrars\UsageRegistrar;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Usage\DatabaseGrantUsageStore;
use SineMacula\Laravel\Authorization\Usage\GrantRoute;
use SineMacula\Laravel\Authorization\Usage\GrantUsageRecorder;
use SineMacula\Laravel\Authorization\Usage\RecordGrantUsage;
use SineMacula\Laravel\Authorization\Usage\StoredGrant;
use Tests\Fixtures\Usage\CountingUsageStore;
use Tests\TestCase;

/**
 * Feature tests for how grant usage tracking is wired: the store bound, which
 * an application may rebind, and the recorder, one per worker; with tracking
 * off nothing listens, and with it on the recorder flushes as the application
 * terminates and after each queued job.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UsageRegistrar::class)]
final class UsageRegistrarTest extends TestCase
{
    /**
     * The package's store is bound by default, and a store the application
     * binds replaces it; the recorder is one per worker.
     *
     * @return void
     */
    public function testTheStoreIsRebindableAndTheRecorderOnePerWorker(): void
    {
        $app = $this->application();

        self::assertInstanceOf(DatabaseGrantUsageStore::class, $app->make(GrantUsageStore::class));

        $store = new CountingUsageStore(new DatabaseGrantUsageStore);

        $app->instance(GrantUsageStore::class, $store);

        self::assertSame($store, $app->make(GrantUsageStore::class));
        self::assertSame($app->make(GrantUsageRecorder::class), $app->make(GrantUsageRecorder::class));
    }

    /**
     * With tracking off nothing listens for queued jobs, no check builds the
     * recorder, and terminating flushes nothing.
     *
     * @return void
     */
    public function testWithTrackingOffNothingListens(): void
    {
        $app = $this->application();

        Bus::fake([RecordGrantUsage::class]);

        $events = $app->make(Dispatcher::class);

        self::assertFalse($events->hasListeners(JobProcessed::class));
        self::assertFalse($events->hasListeners(JobExceptionOccurred::class));

        $app->terminate();

        self::assertFalse($app->resolved(GrantUsageRecorder::class));
        Bus::assertNothingDispatched();
    }

    /**
     * With tracking on, the recorder flushes what it noted as the application
     * terminates and after each queued job, processed or failed; a recorder no
     * check built is never built to flush.
     *
     * @return void
     */
    public function testWithTrackingOnTheRecorderFlushesAtTheEnd(): void
    {
        $app = $this->application();

        Bus::fake([RecordGrantUsage::class]);
        config(['authorization.usage.enabled' => true]);

        $registrar = new UsageRegistrar($app);

        $registrar->boot();

        $events = $app->make(Dispatcher::class);

        $events->dispatch(new JobProcessed('sync', \Mockery::mock(Job::class)));

        self::assertFalse($app->resolved(GrantUsageRecorder::class));

        $recorder = $app->make(GrantUsageRecorder::class);
        $grant    = new StoredGrant(GrantTarget::PERMISSION, 'p', new Reference('user', 'ann'), null, null, null, null);
        $route    = static fn (string $key): GrantRoute => new GrantRoute($key, $grant);

        $recorder->observe([$route('a')]);
        $events->dispatch(new JobProcessed('sync', \Mockery::mock(Job::class)));

        Bus::assertDispatchedTimes(RecordGrantUsage::class, 1);

        $recorder->observe([$route('b')]);
        $events->dispatch(new JobExceptionOccurred('sync', \Mockery::mock(Job::class), new \RuntimeException('failed')));

        Bus::assertDispatchedTimes(RecordGrantUsage::class, 2);

        $recorder->observe([$route('c')]);
        $app->terminate();

        Bus::assertDispatchedTimes(RecordGrantUsage::class, 3);
    }

    /**
     * Return the application the test runs in.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function application(): Application
    {
        self::assertNotNull($this->app);

        return $this->app;
    }
}
