<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

use Carbon\CarbonImmutable;

/**
 * A period grant usage tracking was on (N102), as the UTC half-open interval
 * `[from, until)`: from the first flush or heartbeat that opened it to the last
 * that extended it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CoveragePeriod
{
    /**
     * Create a new coverage period.
     *
     * @param  \Carbon\CarbonImmutable  $from
     * @param  \Carbon\CarbonImmutable  $until
     */
    public function __construct(

        /** When the period began, in UTC, inclusive. */
        public CarbonImmutable $from,

        /** When the period was last extended to, in UTC, exclusive. */
        public CarbonImmutable $until,
    ) {}
}
