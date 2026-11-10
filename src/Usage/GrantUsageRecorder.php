<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

use Illuminate\Contracts\Bus\Dispatcher;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Support\AuthorizationLog;

/**
 * Notes the grant routes a worker's decisions used and sends them to be
 * recorded (N101), never on a check: one for each container that resolves it,
 * held for as long as that container runs, bound only while usage is tracked. A
 * queue worker or a command resolves it once; under Octane each request's
 * sandbox resolves its own.
 *
 * Each route is noted at most once a bucket (`authorization.usage.interval`
 * seconds, see `UsageTracking::bucketOf()`), by its key and its grant's
 * creation; the routes noted are forgotten as a new bucket begins. What is
 * noted is held in memory, and sent only when the request, job or command ends:
 * the registrar calls `flush()` as the container that resolved the recorder
 * terminates and after each queued job (see `Registrars\UsageRegistrar`).
 * Nothing is ever sent from within a check, so a check never waits on the queue
 * or the store, the `sync` queue included.
 *
 * Once the recorder holds `authorization.usage.batch` observations it sets them
 * aside as a batch of their own, each later sent as a job of its own, so no job
 * outgrows a queue's limit. The routes it remembers are bounded too: past ten
 * batches' worth they are forgotten, so a route may then be sent again within
 * its bucket, which its recording ignores. It holds at most ten batches set
 * aside: past that the oldest is dropped, its routes long forgotten by then,
 * and the next job sent names the earliest bucket dropped, from which the store
 * does not extend the coverage, so the routes read `unknown` rather than
 * `unused` over the time lost.
 *
 * A queue that refuses a job is written to the log channel, the observations it
 * carried dropped and their routes forgotten, so a later use notes them again,
 * and the next job sent names them as it names a dropped batch.
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

    /** @var int How many batches the recorder sets aside, at most, before it drops the oldest. */
    private const int HELD = 10;

    /** @var list<array{\SineMacula\Laravel\Authorization\Usage\GrantRoute, int}> The routes noted since the last batch was set aside, each with its bucket. */
    private array $pending = [];

    /** @var list<list<array{\SineMacula\Laravel\Authorization\Usage\GrantRoute, int}>> The batches set aside, oldest first, waiting to be sent. */
    private array $held = [];

    /** @var array<string, true> The routes noted in the current bucket, by key and grant creation. */
    private array $noted = [];

    /** @var int|null The start of the bucket the noted routes were noted in. */
    private ?int $bucket = null;

    /** @var int|null The start of the earliest bucket observations were dropped from since the last flush; null when none were. */
    private ?int $lostSince = null;

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
     * Note the routes a decision used, each once in the current bucket, and set
     * them aside as a batch once a batch's worth is noted; a failure is written
     * to the log channel and never thrown, so a check is never changed by it.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Usage\GrantRoute>  $routes
     * @return void
     */
    public function observe(array $routes): void
    {
        rescue(function () use ($routes): void {
            $this->note($routes);
        }, static function (\Throwable $exception): void {
            AuthorizationLog::warning('Authorization: the grants a check used could not be noted — ' . $exception->getMessage(), [
                'reason' => $exception->getMessage(),
            ]);
        }, false);
    }

    /**
     * Send each batch set aside, and what is noted besides, as a recording job
     * of its own, the first naming any observations dropped since the last
     * flush, or a job of no observations naming them when nothing else is sent;
     * a queue that refuses one is written to the log channel, its observations
     * dropped, and the next job names them.
     *
     * @return void
     */
    public function flush(): void
    {
        $batches = $this->pending === [] ? $this->held : [...$this->held, $this->pending];
        $lost    = $this->lostSince;

        $this->pending   = [];
        $this->held      = [];
        $this->lostSince = null;

        $at = Carbon::now()->getTimestamp();

        foreach ($batches === [] && $lost !== null ? [[]] : $batches as $observed) {
            $lost = $this->send($observed, $at, $lost);
        }

        $this->lostSince = $lost;
    }

    /**
     * Return how many observations are noted and not yet sent, those set aside
     * included.
     *
     * @return int
     */
    public function pending(): int
    {
        return \array_sum(\array_map(\count(...), [$this->pending, ...$this->held]));
    }

    /**
     * Note the routes, each once in the current bucket, and set them aside as a
     * batch once a batch's worth is noted, dropping the oldest batch set aside
     * past the most held.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Usage\GrantRoute>  $routes
     * @return void
     */
    private function note(array $routes): void
    {
        $bucket = UsageTracking::bucketOf(Carbon::now()->getTimestamp(), UsageTracking::interval());
        $batch  = UsageTracking::batch();

        if ($bucket !== $this->bucket || \count($this->noted) >= $batch * self::REMEMBERED) {
            $this->noted  = [];
            $this->bucket = $bucket;
        }

        foreach ($routes as $route) {
            $noted = self::notedAs($route);

            if (isset($this->noted[$noted])) {
                continue;
            }

            $this->noted[$noted] = true;
            $this->pending[]     = [$route, $bucket];
        }

        if (\count($this->pending) < $batch) {
            return;
        }

        $this->held[]  = $this->pending;
        $this->pending = [];

        if (\count($this->held) <= self::HELD) {
            return;
        }

        $this->lostSince = self::earliest($this->lostSince, self::earliestOf(\array_shift($this->held)));
    }

    /**
     * Send the observations as one recording job, naming the earliest bucket
     * dropped before them, and return none; a queue that refuses it is written
     * to the log channel, the observations dropped and their routes forgotten,
     * and the earliest bucket dropped returned, for the next job to name.
     *
     * @param  list<array{\SineMacula\Laravel\Authorization\Usage\GrantRoute, int}>  $observed
     * @param  int  $at
     * @param  int|null  $lostSince
     * @return int|null
     */
    private function send(array $observed, int $at, ?int $lostSince): ?int
    {
        return rescue(function () use ($observed, $at, $lostSince): ?int {
            $this->bus->dispatch(new RecordGrantUsage(UsageBatch::of(\array_map(static fn (array $one): array => $one[0]->observedIn($one[1]), $observed), $at, $lostSince)));

            return null;
        }, function (\Throwable $exception) use ($observed, $lostSince): ?int {
            AuthorizationLog::warning('Authorization: grant usage could not be sent to be recorded — ' . $exception->getMessage(), [
                'observations' => \count($observed),
                'reason'       => $exception->getMessage(),
            ]);

            foreach ($observed as [$route]) {
                unset($this->noted[self::notedAs($route)]);
            }

            return self::earliest($lostSince, self::earliestOf($observed));
        }, false);
    }

    /**
     * Return the start of the earliest bucket the observations were noted in;
     * none for no observations.
     *
     * @param  list<array{\SineMacula\Laravel\Authorization\Usage\GrantRoute, int}>  $observed
     * @return int|null
     */
    private static function earliestOf(array $observed): ?int
    {
        $buckets = \array_column($observed, 1);

        return $buckets === [] ? null : \min($buckets);
    }

    /**
     * Return the earlier of the instants, either of which may be none.
     *
     * @param  int|null  $one
     * @param  int|null  $other
     * @return int|null
     */
    private static function earliest(?int $one, ?int $other): ?int
    {
        return $one === null || $other === null ? $one ?? $other : \min($one, $other);
    }

    /**
     * Return what the route is noted as: its key and its grant's creation.
     *
     * @param  \SineMacula\Laravel\Authorization\Usage\GrantRoute  $route
     * @return string
     */
    private static function notedAs(GrantRoute $route): string
    {
        return $route->key . '@' . $route->grant->createdAt;
    }
}
