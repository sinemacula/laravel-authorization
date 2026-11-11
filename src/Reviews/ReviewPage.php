<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews;

use Carbon\CarbonImmutable;

/**
 * One page of a paged access review (see `AccessReview::page()`): its rows, in
 * the review's order, at most the page's limit of them, the cursor the next
 * page is read with, the instant the review was begun at, and whether the
 * identity's principals could all be listed.
 *
 * `nextCursor` is null on the last page, and set only when at least one more
 * row followed this page when it was read. It is opaque and signed: it binds
 * the query, the reviewer (or the trusted path), the row schema version and the
 * review's instant, and holds only the references the rows already show.
 *
 * `reviewedAt` is frozen when the first page is read and carried by the cursor,
 * so every page classifies each expiry at the same instant. The scan is live,
 * not a snapshot: a row written or revoked between pages may appear or
 * disappear, but a row present throughout is returned exactly once.
 *
 * `isStoredInventoryOnly` is true for a review of holdings filtered by an
 * action (see `ReviewQuery::forAction()`): its rows are the stored grant routes
 * giving the action, and a policy a dynamic `PolicyStore` gives, or a policy
 * attached to a resource, may give it too outside what the review reads, so the
 * rows are never the complete set of places the action is allowed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ReviewPage
{
    /**
     * Create a new review page.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\ReviewRow>  $rows
     * @param  string|null  $nextCursor
     * @param  \Carbon\CarbonImmutable  $reviewedAt
     * @param  bool  $isComplete
     * @param  bool  $isStoredInventoryOnly
     */
    public function __construct(

        /** The rows, in the review's order. */
        public array $rows,

        /** The cursor the next page is read with; null on the last page. */
        public ?string $nextCursor,

        /** The instant the review was begun at, in UTC, against which each row's expiry is read on every page. */
        public CarbonImmutable $reviewedAt,

        /** Whether the identity directory listed every principal of the identity whose holdings were reviewed; true for every other review. */
        public bool $isComplete,

        /** Whether the rows cover only the stored grants, outside which a dynamic or resource policy may give the action; false for a review not filtered by one. */
        public bool $isStoredInventoryOnly = false,
    ) {}

    /**
     * Determine whether this page is the review's last.
     *
     * @return bool
     */
    public function isLast(): bool
    {
        return $this->nextCursor === null;
    }

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
