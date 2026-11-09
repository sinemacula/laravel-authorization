<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Carbon\CarbonImmutable;

/**
 * Where a paged access review stands: the instant the review was begun at,
 * frozen for every page so each expiry is classified the same way throughout,
 * and the sort key of the last row returned, after which the next page starts
 * (see `RowCollector`); none for the first page.
 *
 * A review's position is carried between pages by a signed cursor (see
 * `ReviewCursor`), or held by the stream or the export that reads it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReviewPosition
{
    /**
     * Create a new position.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @param  list<bool|int|string|null>|null  $after
     */
    public function __construct(

        /** The instant the review was begun at, in UTC. */
        public CarbonImmutable $at,

        /** The sort key of the last row returned; null before the first page. */
        public ?array $after = null,
    ) {}

    /**
     * Return the position of a review begun now, before its first page.
     *
     * @return self
     */
    public static function start(): self
    {
        return new self(CarbonImmutable::now('UTC'));
    }

    /**
     * Return the position after the row with the sort key given, in the same
     * review.
     *
     * @param  list<bool|int|string|null>  $key
     * @return self
     */
    public function after(array $key): self
    {
        return new self($this->at, $key);
    }
}
