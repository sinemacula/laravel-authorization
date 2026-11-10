<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

use Carbon\CarbonImmutable;

/**
 * What a usage store keeps of one grant route (N101, N102): the start of the
 * last bucket the route was observed in, and the creation of the grant it was
 * observed through, which tells a regrant's use from the use of the grant it
 * replaced.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ObservedUse
{
    /**
     * Create a new observed use.
     *
     * @param  \Carbon\CarbonImmutable  $lastObservedAt
     * @param  \Carbon\CarbonImmutable|null  $grantCreatedAt
     */
    public function __construct(

        /** The start of the last bucket the route was observed in, in UTC. */
        public CarbonImmutable $lastObservedAt,

        /** The creation of the grant the route was observed through, in UTC; null when it recorded none. */
        public ?CarbonImmutable $grantCreatedAt = null,
    ) {}

    /**
     * Determine whether the use was observed through the grant created at the
     * instant, or a later one, rather than through a grant it replaced: an
     * observation older than the grant's creation is ignored, so a revoked
     * grant made again never inherits the old one's use.
     *
     * @param  \Carbon\CarbonImmutable|null  $createdAt
     * @return bool
     */
    public function isOf(?CarbonImmutable $createdAt): bool
    {
        if ($createdAt === null) {
            return true;
        }

        return $this->grantCreatedAt !== null && $this->grantCreatedAt->getTimestamp() >= $createdAt->getTimestamp();
    }
}
