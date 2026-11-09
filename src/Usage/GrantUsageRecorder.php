<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

use Illuminate\Contracts\Bus\Dispatcher;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Support\AuthorizationLog;

/**
 * Notes the grant routes a worker's decisions used and sends them to be
 * recorded (N101), never inline on a check: one per worker, held for as long as
 * the worker runs, bound only while usage is tracked.
 *
 * Each route is noted at most once a bucket (`authorization.usage.interval`
 * seconds, see `UsageTracking::bucketOf()`), by its key and its grant's
 * creation; the routes noted are forgotten as a new bucket begins. What is
 * noted is held in memory and sent as one queued job (see `RecordGrantUsage`)
 * when the request, job or command ends (the service provider calls `flush()`
 * as the application terminates and after each queued job), or as soon as the
 * worker holds `authorization.usage.batch` observations, so a long-running
 * worker never holds more than that. The routes it remembers are bounded too:
 * past ten batches' worth they are forgotten, so a route may then be sent again
 * within its bucket, which its recording ignores.
 *
 * Sending never reaches a decision: a queue that refuses the job is written to
 * the log channel and its observations dropped, so a check never waits on, or
 * fails with, the store. On the `sync` queue the job runs as it is sent.
 *
 * @phpstan-import-type Observation from \SineMacula\Laravel\Authorization\Usage\UsageBatch
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GrantUsageRecorder
{
    /** @var int How many batches' worth of routes the recorder remembers before it forgets them. */
    private const int REMEMBERED = 10;

    /** @var list<Observation> The observations noted since the last flush. */
    private array $pending = [];

    /** @var array<string, true> The routes noted in the current bucket, by key and grant creation. */
    private array $noted = [];

    /** @var int|null The start of the bucket the noted routes were noted in. */
    private ?int $bucket = null;

    /**
     * Create a new recorder.
     *
     * @param  \Illuminate\Contracts\Bus\Dispatcher  $bus
     */
    public function __construct(

        /** Sends the recording jobs. */
        private readonly Dispatcher $bus,
    ) {}

    /**
     * Note the routes a decision used, each once in the current bucket, and
     * flush once the worker holds a batch's worth.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Usage\GrantRoute>  $routes
     * @return void
     */
    public function observe(array $routes): void
    {
        if ($routes === []) {
            return;
        }

        $bucket = UsageTracking::bucketOf(Carbon::now()->getTimestamp(), UsageTracking::interval());
        $batch  = UsageTracking::batch();

        if ($bucket !== $this->bucket || \count($this->noted) >= $batch * self::REMEMBERED) {
            $this->noted  = [];
            $this->bucket = $bucket;
        }

        foreach ($routes as $route) {
            $noted = $route->key . '@' . $route->grant->createdAt;

            if (isset($this->noted[$noted])) {
                continue;
            }

            $this->noted[$noted] = true;
            $this->pending[]     = $route->observedIn($bucket);
        }

        if (\count($this->pending) < $batch) {
            return;
        }

        $this->flush();
    }

    /**
     * Send what is noted as one recording job, when anything is; a queue that
     * refuses it is written to the log channel and what was noted dropped.
     *
     * @return void
     */
    public function flush(): void
    {
        if ($this->pending === []) {
            return;
        }

        $pending       = $this->pending;
        $this->pending = [];

        $job = new RecordGrantUsage(new UsageBatch($pending, Carbon::now()->getTimestamp()));

        rescue(fn (): mixed => $this->bus->dispatch($job), static function (\Throwable $exception) use ($pending): void {
            AuthorizationLog::warning('Authorization: grant usage could not be sent to be recorded — ' . $exception->getMessage(), [
                'observations' => \count($pending),
                'reason'       => $exception->getMessage(),
            ]);
        }, false);
    }

    /**
     * Return how many observations are noted and not yet sent.
     *
     * @return int
     */
    public function pending(): int
    {
        return \count($this->pending);
    }
}
