<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Carbon\CarbonImmutable;

/**
 * One page of an access review as it was read: its rows, in the review's order,
 * where the next page starts (none on the last), whether the identity's
 * principals could all be listed, and the instant it was read at.
 *
 * `AccessReview` reads every review, page, stream and export through the one
 * read that returns this (D22), then shapes it as a `ReviewResult`, a
 * `ReviewPage` with a signed cursor, a stream of rows or JSON Lines.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PageRead
{
    /**
     * Create a new page as read.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\ReviewRow>  $rows
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewPosition|null  $next
     * @param  bool  $isComplete
     * @param  \Carbon\CarbonImmutable  $at
     */
    public function __construct(

        /** The rows, in the review's order. */
        public array $rows,

        /** Where the next page starts; null when this page is the last. */
        public ?ReviewPosition $next,

        /** Whether the identity directory listed every principal of the identity whose holdings were reviewed; true for every other review. */
        public bool $isComplete,

        /** The instant the review is made at, in UTC, frozen for every page. */
        public CarbonImmutable $at,
    ) {}
}
