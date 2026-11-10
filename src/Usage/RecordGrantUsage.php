<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;

/**
 * The queued job that hands one worker's batch of grant usage observations to
 * the bound usage store (N101), on the queue connection and queue
 * `authorization.usage` names. Recording is monotonic and idempotent (see
 * `Contracts\GrantUsageStore`), so a job retried, delivered twice or run after
 * a later one changes nothing it should not; a job that fails or waits never
 * reaches a decision, which was made and returned before it was sent, since
 * jobs are sent only as a request, command or queued job ends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RecordGrantUsage implements ShouldQueue
{
    use Queueable;

    /**
     * Create a new recording job.
     *
     * @param  \SineMacula\Laravel\Authorization\Usage\UsageBatch  $batch
     */
    public function __construct(

        /** The batch of observations to record. */
        public readonly UsageBatch $batch,
    ) {
        $this->onConnection(UsageTracking::connection());
        $this->onQueue(UsageTracking::queue());
    }

    /**
     * Record the batch in the bound usage store.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\GrantUsageStore  $store
     * @return void
     */
    public function handle(GrantUsageStore $store): void
    {
        $store->record($this->batch);
    }
}
