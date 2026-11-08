<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Database\LiveGrants;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The rows one grantee holds in one grant table within one scope, read and
 * written by the grant service inside its transaction.
 *
 * The scope is a tenant, or the platform when it is null, and an application,
 * or every application when it is null. Grants, re-arms, reads of what is held
 * and revocations stay within the scope, so a role held in one tenant and in
 * another, or platform-wide, are separate grants. Only a grantee's deletion
 * revokes in every scope.
 *
 * A grant inserts its row with insert-or-ignore against the table's unique key,
 * so a grant the grantee already holds, including one a concurrent transaction
 * has just written, never surfaces a unique-constraint violation. When the row
 * was there, it is read back under a row lock and its expiry compared.
 *
 * Every row the writer inserts or rewrites records the actor the call names in
 * `granted_by_type` and `granted_by_id`, both null for console and system work.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GrantTable extends ExpiringGrants
{
    /**
     * Create a new grant table writer.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  string  $column
     * @param  string  $granteeType
     * @param  string  $granteeId
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $grantedBy
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
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

        /** Who makes the grants, recorded on each row written; null for none. */
        private ?Reference $grantedBy = null,

        /** The tenant the grants hold in; null for platform-wide. */
        private ?Reference $tenant = null,

        /** Whether the grants written also hold in the tenants below the tenant. */
        private bool $includeSubtree = true,

        /** The application the grants hold in; null for every application. */
        private ?string $application = null,
    ) {}

    /**
     * Grant the given row with the given expiry, and the writer's reach.
     *
     * Granting what is held with the same expiry and reach changes nothing. A
     * different expiry is written with the reach; the same expiry with a
     * different reach changes the reach alone (D21).
     *
     * @param  string  $id
     * @param  \DateTimeInterface|null  $expiresAt
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantChange
     */
    #[\Override]
    public function grant(string $id, ?\DateTimeInterface $expiresAt): GrantChange
    {
        $change = parent::grant($id, $expiresAt);

        if ($change->outcome !== GrantOutcome::UNCHANGED || $this->reachesBelow($id) === $this->includeSubtree) {
            return $change;
        }

        $this->writeExpiry($id, $change->previousExpiresAt);

        return new GrantChange(GrantOutcome::REACH_CHANGED, $change->previousExpiresAt);
    }

    /**
     * Return the keys of the rows the grantee holds in the scope, among the
     * given ones when a list is given, whether or not the grant has expired.
     *
     * @param  list<string>|null  $ids
     * @return list<string>
     */
    public function held(?array $ids = null): array
    {
        return self::keys($this->inScope()->distinct(), $this->column, $ids);
    }

    /**
     * Return the keys of the rows the grantee holds in the scope, among the
     * given ones, whose grant has not expired at the instant given, else now.
     *
     * @param  list<string>  $ids
     * @param  \Illuminate\Support\Carbon|null  $now
     * @return list<string>
     */
    public function live(array $ids, ?Carbon $now = null): array
    {
        return self::keys(LiveGrants::only($this->inScope(), $this->table, $now)->distinct(), $this->column, $ids);
    }

    /**
     * Return the expiry and the reach of the row the grantee holds live in the
     * scope for the key, at the instant given, else now, read on the write
     * connection: when it expires, null for never, and whether it reaches the
     * tenants below its tenant; null when the grantee holds no live row of it.
     *
     * @param  string  $id
     * @param  \Illuminate\Support\Carbon|null  $now
     * @return array{\Illuminate\Support\Carbon|null, bool}|null
     */
    public function liveRow(string $id, ?Carbon $now = null): ?array
    {
        $row = LiveGrants::only($this->inScope()->useWritePdo(), $this->table, $now)->where($this->column, $id)->first(['expires_at', 'include_subtree']);

        if ($row === null) {
            return null;
        }

        /** @var array{expires_at: mixed, include_subtree: bool|int|string} $columns */
        $columns = (array) $row;

        return [UtcDateTime::toUtc($columns['expires_at']), (bool) $columns['include_subtree']];
    }

    /**
     * Delete the grantee's rows in the scope for the given keys.
     *
     * @param  list<string>  $ids
     * @return void
     */
    public function revoke(array $ids): void
    {
        $this->inScope()->whereIn($this->column, $ids)->delete();
    }

    /**
     * Return whether each of the given rows the grantee holds in the scope
     * reaches the tenants below the tenant, keyed by the granted key, for the
     * events of their revocation.
     *
     * @param  list<string>  $ids
     * @return array<string, bool>
     */
    public function reaches(array $ids): array
    {
        $reaches = [];

        foreach ($this->inScope()->whereIn($this->column, $ids)->get([$this->column . ' as target_id', 'include_subtree']) as $row) {
            /** @var array{target_id: string, include_subtree: bool|int|string} $columns */
            $columns = (array) $row;

            $reaches[$columns['target_id']] = (bool) $columns['include_subtree'];
        }

        return $reaches;
    }

    /**
     * Return every grant the grantee holds, in any scope, as its granted key
     * and the scope it holds in (its tenant, null for platform-wide, and its
     * reach), for the revocation of everything a deleted grantee held.
     *
     * @return list<array{0: string, 1: \SineMacula\Laravel\Authorization\Support\GrantScope}>
     */
    public function grantsInEveryScope(): array
    {
        $grants = [];

        foreach ($this->grantee()->get([$this->column . ' as target_id', 'tenant_type', 'tenant_id', 'include_subtree', 'application']) as $row) {
            /** @var array{target_id: string, tenant_type: string|null, tenant_id: string|null, include_subtree: bool|int|string, application: string|null} $columns */
            $columns  = (array) $row;
            $type     = $columns['tenant_type'];
            $tenant   = $type === null ? null : new Reference($type, (string) $columns['tenant_id']);
            $grants[] = [$columns['target_id'], new GrantScope($tenant, $columns['application'], (bool) $columns['include_subtree'])];
        }

        return $grants;
    }

    /**
     * Delete every row the grantee holds, in every scope.
     *
     * @return void
     */
    public function revokeInEveryScope(): void
    {
        $this->grantee()->delete();
    }

    /**
     * Insert the row in the scope unless the table already holds it, and report
     * whether it was inserted.
     *
     * @param  string  $id
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @return bool
     */
    #[\Override]
    protected function store(string $id, ?Carbon $expiresAt): bool
    {
        $now = Carbon::now();

        return $this->connection->table($this->table)->insertOrIgnore([
            $this->column       => $id,
            'authorizable_type' => $this->granteeType,
            'authorizable_id'   => $this->granteeId,
            'tenant_type'       => $this->tenant?->type,
            'tenant_id'         => $this->tenant?->id,
            'include_subtree'   => $this->includeSubtree,
            'application'       => $this->application,
            'expires_at'        => $expiresAt,
            'granted_by_type'   => $this->grantedBy?->type,
            'granted_by_id'     => $this->grantedBy?->id,
            'created_at'        => $now,
            'updated_at'        => $now,
        ]) === 1;
    }

    /**
     * Read the expiry of the row in the scope under a row lock.
     *
     * @param  string  $id
     * @return \Illuminate\Support\Carbon|null
     */
    #[\Override]
    protected function lockedExpiry(string $id): ?Carbon
    {
        $row = $this->inScope()->where($this->column, $id)->lockForUpdate()->sole(['expires_at']);

        return UtcDateTime::toUtc($row->expires_at);
    }

    /**
     * Write the new expiry, the reach, and the actor making the grant again, to
     * the row in the scope.
     *
     * @param  string  $id
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @return void
     */
    #[\Override]
    protected function writeExpiry(string $id, ?Carbon $expiresAt): void
    {
        $this->inScope()->where($this->column, $id)->update([
            'include_subtree' => $this->includeSubtree,
            'expires_at'      => $expiresAt,
            'granted_by_type' => $this->grantedBy?->type,
            'granted_by_id'   => $this->grantedBy?->id,
            'updated_at'      => Carbon::now(),
        ]);
    }

    /**
     * Determine whether the held row in the scope reaches the tenants below its
     * tenant.
     *
     * @param  string  $id
     * @return bool
     */
    private function reachesBelow(string $id): bool
    {
        // A locking read, as the expiry's: on MySQL a plain read would see the
        // transaction's snapshot rather than the row it has just locked.
        return (bool) $this->inScope()->where($this->column, $id)->lockForUpdate()->value('include_subtree');
    }

    /**
     * Query the grantee's rows in the scope: its tenant, or platform-wide, and
     * its application, or every application.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function inScope(): Builder
    {
        $query = $this->application === null ? $this->grantee()->whereNull('application') : $this->grantee()->where('application', $this->application);

        if ($this->tenant === null) {
            return $query->whereNull('tenant_type')->whereNull('tenant_id');
        }

        return $query->where('tenant_type', $this->tenant->type)->where('tenant_id', $this->tenant->id);
    }

    /**
     * Return the granted keys the query reads, among the given ones when a list
     * is given.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $column
     * @param  list<string>|null  $ids
     * @return list<string>
     */
    private static function keys(Builder $query, string $column, ?array $ids): array
    {
        if ($ids !== null) {
            $query->whereIn($column, $ids);
        }

        return \array_values(\array_map(static fn (mixed $key): string => \is_scalar($key) ? (string) $key : '', $query->pluck($column)->all()));
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
}
