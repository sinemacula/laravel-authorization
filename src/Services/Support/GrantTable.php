<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;

/**
 * The rows one grantee holds in one grant table, read and written by the grant
 * service inside its transaction.
 *
 * Every grant is written platform-wide, for every application: both tenant
 * columns and the application are null. Nothing reads a grant's scope yet, so a
 * row in a tenant or application scope would count everywhere; the service
 * therefore writes none.
 *
 * A grant inserts its row with insert-or-ignore against the table's unique key,
 * so a grant the grantee already holds, including one a concurrent transaction
 * has just written, never surfaces a unique-constraint violation. When the row
 * was there, it is read back under a row lock and its expiry compared.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GrantTable
{
    /**
     * Create a new grant table writer.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  string  $column
     * @param  string  $granteeType
     * @param  string  $granteeId
     */
    public function __construct(

        /** The package connection the grant table lives on. */
        private Connection $connection,

        /** The grant table. */
        private string $table,

        /** The column that names the granted row. */
        private string $column,

        /** The grantee's morph type. */
        private string $granteeType,

        /** The grantee's key. */
        private string $granteeId,
    ) {}

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

        return $this->rewrite($id, $previous, $expiresAt);
    }

    /**
     * Grant the given row with the given expiry unless the grantee holds it
     * already: a live grant is left as it is, and only a grant that has expired
     * is re-armed. Used by a sync, which keeps what the grantee holds.
     *
     * @param  string  $id
     * @param  \DateTimeInterface|null  $expiresAt
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantChange
     */
    public function rearm(string $id, ?\DateTimeInterface $expiresAt): GrantChange
    {
        $expiresAt = UtcDateTime::toUtc($expiresAt);

        if ($this->store($id, $expiresAt)) {
            return new GrantChange(GrantOutcome::GRANTED);
        }

        $previous = $this->lockedExpiry($id);

        if (!self::hasExpired($previous) || self::isSameInstant($previous, $expiresAt)) {
            return new GrantChange(GrantOutcome::UNCHANGED, $previous);
        }

        return $this->rewrite($id, $previous, $expiresAt);
    }

    /**
     * Return the keys of the rows the grantee holds, among the given ones when
     * a list is given, in any scope and whether or not the grant has expired.
     *
     * @param  list<string>|null  $ids
     * @return list<string>
     */
    public function held(?array $ids = null): array
    {
        $query = $this->grantee()->distinct();

        if ($ids !== null) {
            $query->whereIn($this->column, $ids);
        }

        return \array_values(\array_map(static fn (mixed $key): string => \is_scalar($key) ? (string) $key : '', $query->pluck($this->column)->all()));
    }

    /**
     * Delete the grantee's rows for the given keys, in every scope. Until a
     * grant's scope is read, every row counts platform-wide, so a revocation
     * removes each row a check would read as the grant.
     *
     * @param  list<string>  $ids
     * @return void
     */
    public function revoke(array $ids): void
    {
        $this->grantee()->whereIn($this->column, $ids)->delete();
    }

    /**
     * Insert the platform-wide row unless the table already holds it, and
     * report whether it was inserted.
     *
     * @param  string  $id
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @return bool
     */
    private function store(string $id, ?Carbon $expiresAt): bool
    {
        $now = Carbon::now();

        return $this->connection->table($this->table)->insertOrIgnore([
            $this->column       => $id,
            'authorizable_type' => $this->granteeType,
            'authorizable_id'   => $this->granteeId,
            'expires_at'        => $expiresAt,
            'created_at'        => $now,
            'updated_at'        => $now,
        ]) === 1;
    }

    /**
     * Read the expiry of the platform-wide row under a row lock.
     *
     * @param  string  $id
     * @return \Illuminate\Support\Carbon|null
     */
    private function lockedExpiry(string $id): ?Carbon
    {
        $row = $this->platform($id)->lockForUpdate()->sole(['expires_at']);

        return UtcDateTime::toUtc($row->expires_at);
    }

    /**
     * Write the new expiry to the platform-wide row and report the change: a
     * re-armed grant when the previous expiry had passed, else a changed one.
     *
     * @param  string  $id
     * @param  \Illuminate\Support\Carbon|null  $previous
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantChange
     */
    private function rewrite(string $id, ?Carbon $previous, ?Carbon $expiresAt): GrantChange
    {
        $this->platform($id)->update([
            'expires_at' => $expiresAt,
            'updated_at' => Carbon::now(),
        ]);

        return new GrantChange(self::hasExpired($previous) ? GrantOutcome::REARMED : GrantOutcome::EXPIRY_CHANGED, $previous);
    }

    /**
     * Query the grantee's platform-wide row for the given key.
     *
     * @param  string  $id
     * @return \Illuminate\Database\Query\Builder
     */
    private function platform(string $id): Builder
    {
        return $this->grantee()
            ->where($this->column, $id)
            ->whereNull('tenant_type')
            ->whereNull('tenant_id')
            ->whereNull('application');
    }

    /**
     * Query every row the grantee holds in the table.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function grantee(): Builder
    {
        return $this->connection->table($this->table)
            ->where('authorizable_type', $this->granteeType)
            ->where('authorizable_id', $this->granteeId);
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
     * Determine whether an expiry has passed. A grant with no expiry never
     * expires.
     *
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @return bool
     */
    private static function hasExpired(?Carbon $expiresAt): bool
    {
        return $expiresAt !== null && !$expiresAt->isFuture();
    }
}
