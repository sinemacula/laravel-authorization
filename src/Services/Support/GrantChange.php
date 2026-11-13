<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;

/**
 * What one grant row write changed, with the expiry the row carried before it,
 * for the expiry-changed event, and whether it reached below its tenant before.
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
     * @param  bool|null  $previousReach
     */
    public function __construct(

        /** What the write changed. */
        public GrantOutcome $outcome,

        /** The expiry the row carried before the write, in UTC. */
        public ?Carbon $previousExpiresAt = null,

        /** Whether the row reached below its tenant before the write; null for a new row or one with no reach. */
        public ?bool $previousReach = null,
    ) {}

    /**
     * Return the expiry the row carries after the write: the one it kept when
     * the write changed its reach alone, else the one given, which it was
     * written with.
     *
     * @param  \DateTimeInterface|null  $expiresAt
     * @return \DateTimeInterface|null
     */
    public function expiryAfter(?\DateTimeInterface $expiresAt): ?\DateTimeInterface
    {
        return $this->outcome === GrantOutcome::REACH_CHANGED ? $this->previousExpiresAt : $expiresAt;
    }

    /**
     * Determine whether the write changed the row of the key while the keys
     * list it.
     *
     * @param  string  $id
     * @param  list<string>  $ids
     * @return bool
     */
    public function changesAnyOf(string $id, array $ids): bool
    {
        return $this->outcome !== GrantOutcome::UNCHANGED && \in_array($id, $ids, true);
    }

    /**
     * Determine whether the write may let the grantee hold the row where or
     * when it did not: a new or re-armed grant, a reach widened below its
     * tenant, or an expiry made later or lifted. Given the expiry and the reach
     * the row was written with.
     *
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  bool  $includeSubtree
     * @return bool
     */
    public function isWidening(?\DateTimeInterface $expiresAt, bool $includeSubtree): bool
    {
        return match ($this->outcome) {
            GrantOutcome::GRANTED, GrantOutcome::REARMED => true,
            GrantOutcome::REACH_CHANGED                  => $includeSubtree,
            GrantOutcome::EXPIRY_CHANGED                 => $this->isLater($expiresAt) || ($includeSubtree && $this->previousReach !== true),
            default                                      => false,
        };
    }

    /**
     * Determine whether the expiry given ends after the one the row carried
     * before, none counting as never.
     *
     * @param  \DateTimeInterface|null  $expiresAt
     * @return bool
     */
    private function isLater(?\DateTimeInterface $expiresAt): bool
    {
        if ($this->previousExpiresAt === null) {
            return false;
        }

        return $expiresAt === null || $expiresAt > $this->previousExpiresAt;
    }
}
