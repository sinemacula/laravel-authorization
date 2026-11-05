<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;

/**
 * What one grant row write changed, with the expiry the row carried before it,
 * for the expiry-changed event.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GrantChange
{
    /**
     * Create a new grant change.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantOutcome  $outcome
     * @param  \Illuminate\Support\Carbon|null  $previousExpiresAt
     */
    public function __construct(

        /** What the write changed. */
        public GrantOutcome $outcome,

        /** The expiry the row carried before the write, in UTC. */
        public ?Carbon $previousExpiresAt = null,
    ) {}
}
