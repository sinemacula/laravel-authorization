<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

/**
 * A batch of grant usage observations one worker flushes as one queued job
 * (N101), as plain values, so it travels through any queue: each observation
 * names its route by key (see `GrantUsageKey`), the stored grant it starts from
 * (see `StoredGrant`) and the start of the bucket it was observed in, and the
 * batch names the instant it was flushed at, to which the coverage extends.
 *
 * A batch with no observations only extends the coverage, as the heartbeat
 * does.
 *
 * @phpstan-type Observation array{
 *     grant_key: string,
 *     grant_source: string,
 *     grant_id: string,
 *     authorizable_type: string,
 *     authorizable_id: string,
 *     tenant_type: string|null,
 *     tenant_id: string|null,
 *     application: string|null,
 *     grant_created_at: int|null,
 *     last_observed_at: int
 * }
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class UsageBatch
{
    /**
     * Create a new batch.
     *
     * @param  list<Observation>  $observations
     * @param  int  $at
     */
    public function __construct(

        /** The observations, each a route observed in a bucket, every timestamp in UTC. */
        public array $observations,

        /** When the batch was flushed, as a UTC timestamp. */
        public int $at,
    ) {}
}
