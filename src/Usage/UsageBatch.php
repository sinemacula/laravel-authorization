<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

/**
 * A batch of grant usage observations one worker flushes as one queued job
 * (N101), as compact plain values, so it travels through any queue well within
 * its limit on a job's size: each stored grant the routes start from once (see
 * `StoredGrant`), and each observation as its route's key (see
 * `GrantUsageKey`), the index of its grant and the start of the bucket it was
 * observed in. The batch names the instant it was flushed at, to which the
 * coverage extends, and, when the worker dropped observations before it, the
 * start of the earliest bucket they were noted in, from which the coverage is
 * not extended (see `Contracts\GrantUsageStore`).
 *
 * `observations()` returns each observation whole, as a store records it. A
 * batch with no observations only extends the coverage, as the heartbeat does.
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
 * @phpstan-type BatchGrant array{string, string, string, string, string|null, string|null, string|null, int|null}
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class UsageBatch
{
    /** @var list<string> The columns of a stored grant, in the order a batch holds them. */
    private const array GRANT = ['grant_source', 'grant_id', 'authorizable_type', 'authorizable_id', 'tenant_type', 'tenant_id', 'application', 'grant_created_at'];

    /**
     * Create a new batch.
     *
     * @param  list<BatchGrant>  $grants
     * @param  list<array{string, int, int}>  $routes
     * @param  int  $at
     * @param  int|null  $lostSince
     */
    public function __construct(

        /** The distinct stored grants the routes start from, each its columns in the order of `GRANT`. */
        public array $grants,

        /** The observations, each its route's key, the index of its grant and the start of its bucket, in UTC. */
        public array $routes,

        /** When the batch was flushed, as a UTC timestamp. */
        public int $at,

        /** The start of the earliest bucket the worker dropped observations from before the batch, in UTC; null when it dropped none. */
        public ?int $lostSince = null,
    ) {}

    /**
     * Return the batch of the observations, each stored grant held once.
     *
     * @param  list<Observation>  $observations
     * @param  int  $at
     * @param  int|null  $lostSince
     * @return self
     */
    public static function of(array $observations, int $at, ?int $lostSince = null): self
    {
        $grants  = [];
        $indexes = [];
        $routes  = [];

        foreach ($observations as $observation) {
            /** @var BatchGrant $grant */
            $grant    = \array_map(static fn (string $column): int|string|null => $observation[$column], self::GRANT);
            $identity = \serialize($grant);

            if (!isset($indexes[$identity])) {
                $grants[]           = $grant;
                $indexes[$identity] = \count($grants) - 1;
            }

            $routes[] = [$observation['grant_key'], $indexes[$identity], $observation['last_observed_at']];
        }

        return new self($grants, $routes, $at, $lostSince);
    }

    /**
     * Return each observation whole, as a store records it.
     *
     * @return list<Observation>
     */
    public function observations(): array
    {
        $observations = [];

        foreach ($this->routes as [$key, $grant, $bucket]) {
            /** @var Observation $observation */
            $observation = ['grant_key' => $key, ...\array_combine(self::GRANT, $this->grants[$grant]), 'last_observed_at' => $bucket];

            $observations[] = $observation;
        }

        return $observations;
    }
}
