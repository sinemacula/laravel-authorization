<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

/**
 * What a sync through the management services changed, by the primary key of
 * each role, permission or policy.
 *
 * A sync grants what the grantee did not hold, re-arms what it held but had
 * expired, and revokes what it held but the sync does not list. A grant that is
 * listed and live is left as it is, so it appears in none of the lists.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SyncResult
{
    /**
     * Create a new sync result.
     *
     * @param  list<string>  $granted
     * @param  list<string>  $rearmed
     * @param  list<string>  $revoked
     */
    public function __construct(

        /** Keys the grantee did not hold and now does. */
        public array $granted = [],

        /** Keys whose expired grant was re-armed. */
        public array $rearmed = [],

        /** Keys the grantee held and no longer does. */
        public array $revoked = [],
    ) {}

    /**
     * Determine whether the sync wrote anything.
     *
     * @return bool
     */
    public function isChange(): bool
    {
        return $this->granted !== [] || $this->rearmed !== [] || $this->revoked !== [];
    }
}
