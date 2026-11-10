<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Usage;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;
use SineMacula\Laravel\Authorization\Usage\UsageBatch;

/**
 * A usage store an application might bind in the package's place: it passes
 * every call to the store it wraps, counting the lookups of routes, the reads
 * of coverage and the batches recorded.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CountingUsageStore implements GrantUsageStore
{
    /** @var int How many times routes were looked up. */
    public int $lookups = 0;

    /** @var int How many times coverage was read. */
    public int $coverageReads = 0;

    /** @var list<\SineMacula\Laravel\Authorization\Usage\UsageBatch> The batches recorded, in order. */
    public array $batches = [];

    /**
     * Create a new counting store.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\GrantUsageStore  $store
     */
    public function __construct(

        /** The store every call is passed to. */
        private readonly GrantUsageStore $store,
    ) {}

    /**
     * Record the batch in the wrapped store, counting it.
     *
     * @param  \SineMacula\Laravel\Authorization\Usage\UsageBatch  $batch
     * @return void
     */
    #[\Override]
    public function record(UsageBatch $batch): void
    {
        $this->batches[] = $batch;

        $this->store->record($batch);
    }

    /**
     * Look the routes up in the wrapped store, counting the lookup.
     *
     * @param  list<string>  $keys
     * @return array<string, \SineMacula\Laravel\Authorization\Usage\ObservedUse>
     */
    #[\Override]
    public function lastObserved(array $keys): array
    {
        $this->lookups++;

        return $this->store->lastObserved($keys);
    }

    /**
     * Read the coverage from the wrapped store, counting the read.
     *
     * @param  \Carbon\CarbonImmutable  $from
     * @param  \Carbon\CarbonImmutable  $until
     * @return list<\SineMacula\Laravel\Authorization\Usage\CoveragePeriod>
     */
    #[\Override]
    public function coverage(CarbonImmutable $from, CarbonImmutable $until): array
    {
        $this->coverageReads++;

        return $this->store->coverage($from, $until);
    }
}
