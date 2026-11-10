<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authorization\Reviews\Enums\UsageStatus;

/**
 * What an access review knows of one row's use (N94), its `usage` field:
 *
 * - `status`: `used` when the route was observed in use within the window,
 *   `unused` only when tracking covered the whole window and the route was
 *   never observed in it, else `unknown`: tracking was off, its coverage of the
 *   window was incomplete, or the route's source cannot report its use. A
 *   missing observation alone is never taken as proof of non-use;
 * - `last_observed_at`: the start of the last bucket the route was observed in,
 *   through the grant as it stands now (a revoked grant's use is never carried
 *   over to a regrant), so it was last used within the interval that starts
 *   there; null when none is known;
 * - `coverage_from`, `coverage_until`: the latest period tracking was on that
 *   overlaps the window, null for none.
 *
 * The window runs from the later of the review's `since` and the grant's
 * creation to the review's instant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RowUsage
{
    /**
     * Create a new row usage.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\UsageStatus  $status
     * @param  \Carbon\CarbonImmutable|null  $lastObservedAt
     * @param  \Carbon\CarbonImmutable|null  $coverageFrom
     * @param  \Carbon\CarbonImmutable|null  $coverageUntil
     */
    public function __construct(

        /** Whether the route was used, unused or its use is unknown. */
        public UsageStatus $status,

        /** The start of the last bucket the route was observed in, in UTC; null when none is known. */
        public ?CarbonImmutable $lastObservedAt = null,

        /** When the latest period tracking was on that overlaps the window began, in UTC; null for none. */
        public ?CarbonImmutable $coverageFrom = null,

        /** When that period was last extended to, in UTC; null for none. */
        public ?CarbonImmutable $coverageUntil = null,
    ) {}

    /**
     * Return the usage of a row whose use is not known at all.
     *
     * @return self
     */
    public static function unknown(): self
    {
        return new self(UsageStatus::UNKNOWN);
    }

    /**
     * Return the usage as plain values, as a review row's versioned shape holds
     * it.
     *
     * @return array{status: string, last_observed_at: string|null, coverage_from: string|null, coverage_until: string|null}
     */
    public function toArray(): array
    {
        return [
            'status'           => $this->status->value,
            'last_observed_at' => ReviewRow::instant($this->lastObservedAt),
            'coverage_from'    => ReviewRow::instant($this->coverageFrom),
            'coverage_until'   => ReviewRow::instant($this->coverageUntil),
        ];
    }
}
