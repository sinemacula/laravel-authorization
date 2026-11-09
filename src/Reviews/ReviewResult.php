<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews;

use Carbon\CarbonImmutable;

/**
 * What an access review returns, admitted or trusted: its first page (see
 * `ReviewPage`) as a bounded list: its rows, in the review's order, at most its
 * limit of them, whether more were left out, whether the identity's principals
 * could all be listed, and the instant it was made at.
 *
 * `isTruncated` is exact: true only when at least one row was left out.
 * `isComplete` is false only for a review of an identity's holdings whose
 * directory could not list every principal (N81); a principal left out of that
 * list may hold grants the review could not read.
 *
 * A refused review returns nothing at all: no rows, counts, truncation or
 * completeness (see `AccessReview`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ReviewResult
{
    /**
     * Create a new review result.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\ReviewRow>  $rows
     * @param  bool  $isTruncated
     * @param  bool  $isComplete
     * @param  \Carbon\CarbonImmutable  $reviewedAt
     */
    public function __construct(

        /** The rows, in the review's order. */
        public array $rows,

        /** Whether at least one row was left out by the limit. */
        public bool $isTruncated,

        /** Whether the identity directory listed every principal of the identity whose holdings were reviewed; true for every other review. */
        public bool $isComplete,

        /** The instant the review was made at, in UTC, against which each row's expiry is read. */
        public CarbonImmutable $reviewedAt,
    ) {}

    /**
     * Return each row in its versioned shape.
     *
     * @return list<array<string, mixed>>
     */
    public function toArray(): array
    {
        return \array_map(static fn (ReviewRow $row): array => $row->toArray(), $this->rows);
    }
}
