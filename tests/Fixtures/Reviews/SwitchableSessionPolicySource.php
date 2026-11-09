<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Reviews;

use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Subject;

/**
 * A session policy source whose scopes a test changes part way through a
 * review, as a credential's scopes may change while a long export runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SwitchableSessionPolicySource implements SessionPolicySource
{
    /**
     * Create a new switchable source.
     *
     * @param  list<string>|null  $scopes
     */
    public function __construct(

        /** The scopes every session carries; null for no cap. */
        public ?array $scopes = null,
    ) {}

    /**
     * Return the scopes every session carries.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<string>|null
     */
    #[\Override]
    public function scopesFor(Subject $subject): ?array
    {
        return $this->scopes;
    }
}
