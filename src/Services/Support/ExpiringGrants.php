<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;

/**
 * Grants that carry an optional expiry, written inside the caller's
 * transaction: a grantee's grants in one grant table and scope, or a role's
 * grants of permissions.
 *
 * A grant of what is not held stores a new row. Granting what is held with the
 * same expiry changes nothing; any other expiry is written, re-arming a grant
 * that had expired or changing a live one's. A re-arm, as a sync makes it,
 * writes only a grant that had expired and leaves a live one as it is. Each
 * write reports what it changed and the expiry the row carried before.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract readonly class ExpiringGrants
{
    /**
     * Grant the given row with the given expiry.
     *
     * Granting what is held with the same expiry changes nothing. Any other
     * expiry is written: a grant that had expired is re-armed, and a live
     * grant's expiry is changed.
     *
     * @param  string  $id
     * @param  \DateTimeInterface|null  $expiresAt
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantChange
     */
    public function grant(string $id, ?\DateTimeInterface $expiresAt): GrantChange
    {
        $expiresAt = UtcDateTime::toUtc($expiresAt);

        if ($this->store($id, $expiresAt)) {
            return new GrantChange(GrantOutcome::GRANTED);
        }

        $previous = $this->lockedExpiry($id);

        if (self::isSameInstant($previous, $expiresAt)) {
            return new GrantChange(GrantOutcome::UNCHANGED, $previous);
        }

        return $this->rewrite($id, $previous, $expiresAt, Carbon::now('UTC'));
    }

    /**
     * Grant the given row with the given expiry unless the grantee holds it
     * already: a live grant is left as it is, and only a grant that has expired
     * is re-armed. Used by a sync, which keeps what the grantee holds.
     *
     * Whether the grant is live is judged at the instant given, else now, so a
     * sync that judged which of its rows are live at one instant, and decided
     * only those that were not, re-arms exactly those: a row live then is left
     * as it is even when it expires before it is written.
     *
     * @param  string  $id
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Support\Carbon|null  $now
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantChange
     */
    public function rearm(string $id, ?\DateTimeInterface $expiresAt, ?Carbon $now = null): GrantChange
    {
        $expiresAt = UtcDateTime::toUtc($expiresAt);
        $now ??= Carbon::now('UTC');

        if ($this->store($id, $expiresAt)) {
            return new GrantChange(GrantOutcome::GRANTED);
        }

        $previous = $this->lockedExpiry($id);

        if (!self::hasExpired($previous, $now) || self::isSameInstant($previous, $expiresAt)) {
            return new GrantChange(GrantOutcome::UNCHANGED, $previous);
        }

        return $this->rewrite($id, $previous, $expiresAt, $now);
    }

    /**
     * Store the row with the given expiry unless it is held already, and report
     * whether it was stored.
     *
     * @param  string  $id
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @return bool
     */
    abstract protected function store(string $id, ?Carbon $expiresAt): bool;

    /**
     * Read the expiry of the held row under a row lock.
     *
     * @param  string  $id
     * @return \Illuminate\Support\Carbon|null
     */
    abstract protected function lockedExpiry(string $id): ?Carbon;

    /**
     * Write the new expiry to the held row.
     *
     * @param  string  $id
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @return void
     */
    abstract protected function writeExpiry(string $id, ?Carbon $expiresAt): void;

    /**
     * Write the new expiry and report the change: a re-armed grant when the
     * previous expiry had passed at the instant given, else a changed one.
     *
     * @param  string  $id
     * @param  \Illuminate\Support\Carbon|null  $previous
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @param  \Illuminate\Support\Carbon  $now
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantChange
     */
    private function rewrite(string $id, ?Carbon $previous, ?Carbon $expiresAt, Carbon $now): GrantChange
    {
        $this->writeExpiry($id, $expiresAt);

        return new GrantChange(self::hasExpired($previous, $now) ? GrantOutcome::REARMED : GrantOutcome::EXPIRY_CHANGED, $previous);
    }

    /**
     * Determine whether two expiries are the same instant, two nulls (forever)
     * included.
     *
     * @param  \Illuminate\Support\Carbon|null  $left
     * @param  \Illuminate\Support\Carbon|null  $right
     * @return bool
     */
    private static function isSameInstant(?Carbon $left, ?Carbon $right): bool
    {
        return $left?->getTimestamp() === $right?->getTimestamp();
    }

    /**
     * Determine whether an expiry has passed at the instant given: it is not
     * after it. A grant with no expiry never expires.
     *
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @param  \Illuminate\Support\Carbon  $now
     * @return bool
     */
    private static function hasExpired(?Carbon $expiresAt, Carbon $now): bool
    {
        return $expiresAt !== null && $expiresAt->lessThanOrEqualTo($now);
    }
}
