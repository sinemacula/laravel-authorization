<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The permission boundary one grantee has in one scope, read and written by the
 * boundary service inside its transaction.
 *
 * The scope is a tenant, or the platform when it is null; a grantee has at most
 * one boundary in each. Setting one inserts its row with insert-or-ignore
 * against the table's unique key, so setting a boundary where the grantee has
 * one, including one a concurrent transaction has just set, never surfaces a
 * unique-constraint violation: the row is read back under a row lock and
 * rewritten when its policy or its reach differs, and left alone otherwise.
 *
 * An ignored insert is only ever reported once a row is read back: one that
 * leaves no row, as when a concurrent call removed it in between, is tried
 * again, and when that leaves none either, nothing is reported set. On MySQL
 * that is a policy deleted at the same moment, whose foreign key failure
 * `INSERT IGNORE` turns into a warning, so a boundary is never reported, nor
 * its event dispatched, with no row to bear it out.
 *
 * Every row the writer inserts or rewrites records the actor the call names in
 * `granted_by_type` and `granted_by_id`, both null for console and system work.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class BoundaryTable
{
    /**
     * Create a new boundary table writer.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $grantedBy
     */
    public function __construct(

        /** The package connection the table lives on. */
        private Connection $connection,

        /** The boundaries table. */
        private string $table,

        /** The grantee whose boundary is read or written. */
        private Reference $grantee,

        /** The tenant the boundary holds in; null for platform-wide. */
        private ?Reference $tenant = null,

        /** Whether the boundary written also holds in the tenants below the tenant. */
        private bool $includeSubtree = true,

        /** Who sets the boundary, recorded on each row written; null for none. */
        private ?Reference $grantedBy = null,
    ) {}

    /**
     * Set the policy with the given key as the grantee's boundary in the scope,
     * with the writer's reach, and report what changed with the key of the
     * policy it replaced, when it replaced another; null when no row could be
     * written, even once tried again, so nothing is set.
     *
     * @param  string  $policy
     * @return array{\SineMacula\Laravel\Authorization\Enums\GrantOutcome, string|null}|null
     */
    public function set(string $policy): ?array
    {
        // Once the insert is ignored, a locking read: on MySQL a plain read
        // would see the transaction's snapshot rather than the row it has just
        // locked. A row a concurrent call removed in between is set afresh.
        for ($attempt = 0; $attempt < 2; $attempt++) {
            if ($this->wasInserted($policy)) {
                return [GrantOutcome::GRANTED, null];
            }

            $held = $this->held();

            if ($held !== null) {
                return $this->rewritten($policy, ...$held);
            }
        }

        return null;
    }

    /**
     * Remove the grantee's boundary in the scope, and return the key of the
     * policy it was with the scope it held in and the reach it had, or null
     * when the grantee had none there.
     *
     * @return array{string, \SineMacula\Laravel\Authorization\Support\GrantScope}|null
     */
    public function remove(): ?array
    {
        // A locking read, so what is reported is the row as it is deleted.
        $held = $this->held();

        if ($held === null) {
            return null;
        }

        $this->inScope()->delete();

        return [$held[0], new GrantScope($this->tenant, null, $held[1] || $this->tenant === null)];
    }

    /**
     * Remove the grantee's boundaries in every scope, and return the key of
     * each policy with the scope it held in, for the events of the removal.
     *
     * @return list<array{string, \SineMacula\Laravel\Authorization\Support\GrantScope}>
     */
    public function removeEverywhere(): array
    {
        $removed = $this->everywhere();

        $this->grantee()->delete();

        return $removed;
    }

    /**
     * Read the grantee's boundaries in every scope, under a row lock, as the
     * key of each policy with the scope it holds in, so a removal can be
     * decided before anything is removed.
     *
     * @return list<array{string, \SineMacula\Laravel\Authorization\Support\GrantScope}>
     */
    public function everywhere(): array
    {
        $boundaries = [];

        foreach ($this->grantee()->lockForUpdate()->get(['policy_id', 'tenant_type', 'tenant_id', 'include_subtree']) as $row) {
            /** @var array{policy_id: int|string, tenant_type: string|null, tenant_id: string|null, include_subtree: bool|int|string} $columns */
            $columns      = (array) $row;
            $tenant       = $columns['tenant_type'] === null ? null : new Reference($columns['tenant_type'], (string) $columns['tenant_id']);
            $boundaries[] = [(string) $columns['policy_id'], new GrantScope($tenant, null, (bool) $columns['include_subtree'] || $tenant === null)];
        }

        return $boundaries;
    }

    /**
     * Read the key of the policy the grantee's boundary in the scope is and its
     * reach, under a row lock, or null when it has none there, so a removal can
     * be decided before anything is removed.
     *
     * @return array{string, bool}|null
     */
    public function held(): ?array
    {
        $row = $this->inScope()->lockForUpdate()->first(['policy_id', 'include_subtree']);

        if ($row === null) {
            return null;
        }

        /** @var array{policy_id: int|string, include_subtree: bool|int|string} $columns */
        $columns = (array) $row;

        return [(string) $columns['policy_id'], (bool) $columns['include_subtree']];
    }

    /**
     * Rewrite the grantee's boundary in the scope, held as the policy with the
     * previous key and the reach, to the policy with the given key and the
     * writer's reach, and report what changed with the key of the policy it
     * replaced, when it replaced another.
     *
     * @param  string  $policy
     * @param  string  $previous
     * @param  bool  $reach
     * @return array{\SineMacula\Laravel\Authorization\Enums\GrantOutcome, string|null}
     */
    private function rewritten(string $policy, string $previous, bool $reach): array
    {
        if ($previous === $policy && $reach === $this->includeSubtree) {
            return [GrantOutcome::UNCHANGED, null];
        }

        $this->inScope()->update([
            'policy_id'       => $policy,
            'include_subtree' => $this->includeSubtree,
            'granted_by_type' => $this->grantedBy?->type,
            'granted_by_id'   => $this->grantedBy?->id,
            'updated_at'      => Carbon::now(),
        ]);

        return $previous === $policy ? [GrantOutcome::REACH_CHANGED, null] : [GrantOutcome::REPLACED, $previous];
    }

    /**
     * Insert the boundary in the scope unless the grantee has one there, and
     * report whether it was inserted.
     *
     * @param  string  $policy
     * @return bool
     */
    private function wasInserted(string $policy): bool
    {
        $now = Carbon::now();

        return $this->connection->table($this->table)->insertOrIgnore([
            'policy_id'         => $policy,
            'authorizable_type' => $this->grantee->type,
            'authorizable_id'   => $this->grantee->id,
            'tenant_type'       => $this->tenant?->type,
            'tenant_id'         => $this->tenant?->id,
            'include_subtree'   => $this->includeSubtree,
            'granted_by_type'   => $this->grantedBy?->type,
            'granted_by_id'     => $this->grantedBy?->id,
            'created_at'        => $now,
            'updated_at'        => $now,
        ]) === 1;
    }

    /**
     * Query the grantee's boundary in the scope: its tenant, or platform-wide.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function inScope(): Builder
    {
        if ($this->tenant === null) {
            return $this->grantee()->whereNull('tenant_type')->whereNull('tenant_id');
        }

        return $this->grantee()->where('tenant_type', $this->tenant->type)->where('tenant_id', $this->tenant->id);
    }

    /**
     * Query every boundary the grantee has in the table.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function grantee(): Builder
    {
        return $this->connection->table($this->table)
            ->where('authorizable_type', $this->grantee->type)
            ->where('authorizable_id', $this->grantee->id);
    }
}
