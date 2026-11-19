<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
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
 * write reports what it changed and the expiry, and any reach, the row carried
 * before.
 *
 * A held row is only ever reported once it is read back: one a concurrent call
 * removed between the ignored store and the read is stored afresh, once, and
 * when that leaves no row either, as a granted row deleted does, the write
 * reports nothing and writes nothing. A store an integrity constraint refuses,
 * a granted row deleted or a concurrent duplicate, rolls back to a savepoint of
 * its own, so the caller's transaction stays usable on PostgreSQL.
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
     * grant's expiry is changed. Null when no row could be written.
     *
     * @param  string  $id
     * @param  \DateTimeInterface|null  $expiresAt
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantChange|null
     */
    public function grant(string $id, ?\DateTimeInterface $expiresAt): ?GrantChange
    {
        $expiresAt = UtcDateTime::toUtc($expiresAt);
        $held      = $this->written($id, $expiresAt);

        if ($held?->outcome !== GrantOutcome::UNCHANGED || self::isSameInstant($held->previousExpiresAt, $expiresAt)) {
            return $held;
        }

        return $this->rewrite($id, $held, $expiresAt, Carbon::now('UTC'));
    }

    /**
     * Grant the given row with the given expiry unless the grantee holds it
     * already: a live grant is left as it is, and only a grant that has expired
     * is re-armed. Used by a sync, which keeps what the grantee holds.
     *
     * Whether the grant is live is judged at the instant given, else now, so a
     * sync that judged which of its rows are live at one instant, and decided
     * only those that were not, re-arms exactly those: a row live then is left
     * as it is even when it expires before it is written. Null when no row
     * could be written.
     *
     * @param  string  $id
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Support\Carbon|null  $now
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantChange|null
     */
    public function rearm(string $id, ?\DateTimeInterface $expiresAt, ?Carbon $now = null): ?GrantChange
    {
        $expiresAt = UtcDateTime::toUtc($expiresAt);
        $now ??= Carbon::now('UTC');
        $held = $this->written($id, $expiresAt);

        if ($held?->outcome !== GrantOutcome::UNCHANGED || !self::hasExpired($held->previousExpiresAt, $now) || self::isSameInstant($held->previousExpiresAt, $expiresAt)) {
            return $held;
        }

        return $this->rewrite($id, $held, $expiresAt, $now);
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
     * Read the held row under a row lock, as a write that left it as it was:
     * its expiry and, for grants that carry one, its reach; null when it is not
     * there.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantChange|null
     */
    abstract protected function lockedRow(string $id): ?GrantChange;

    /**
     * Write the new expiry to the held row.
     *
     * @param  string  $id
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @return void
     */
    abstract protected function writeExpiry(string $id, ?Carbon $expiresAt): void;

    /**
     * Run the insert in a savepoint on the connection, and report whether it
     * stored the row: not when an integrity constraint refused it, which rolls
     * back the savepoint alone. Any other failure is thrown.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \Closure(): bool  $insert
     * @return bool
     *
     * @throws \Illuminate\Database\QueryException
     * @throws \Throwable
     */
    protected static function inserted(Connection $connection, \Closure $insert): bool
    {
        try {
            return $connection->transaction($insert);
        } catch (QueryException $exception) {
            // SQLSTATE class 23: the row's only constraints are its keys.
            if (!\str_starts_with((string) $exception->getCode(), '23')) {
                throw $exception;
            }

            return false;
        }
    }

    /**
     * Store the row, else read the held row under a row lock, storing afresh,
     * once, a held row a concurrent call removed in between; null when neither
     * leaves a row.
     *
     * @param  string  $id
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantChange|null
     */
    private function written(string $id, ?Carbon $expiresAt): ?GrantChange
    {
        for ($attempt = 0; $attempt < 2; $attempt++) {
            if ($this->store($id, $expiresAt)) {
                return new GrantChange(GrantOutcome::GRANTED);
            }

            $held = $this->lockedRow($id);

            if ($held !== null) {
                return $held;
            }
        }

        return null;
    }

    /**
     * Write the new expiry and report the change: a re-armed grant when the
     * previous expiry had passed at the instant given, else a changed one.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\Authorization\Services\Support\GrantChange  $held
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @param  \Illuminate\Support\Carbon  $now
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantChange
     */
    private function rewrite(string $id, GrantChange $held, ?Carbon $expiresAt, Carbon $now): GrantChange
    {
        $this->writeExpiry($id, $expiresAt);

        $outcome = self::hasExpired($held->previousExpiresAt, $now) ? GrantOutcome::REARMED : GrantOutcome::EXPIRY_CHANGED;

        return new GrantChange($outcome, $held->previousExpiresAt, $held->previousReach);
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
