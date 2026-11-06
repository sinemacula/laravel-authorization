<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The guardrails of one scope, read and written by the guardrail service inside
 * its transaction.
 *
 * The scope is a tenant, or the platform when it is null; a policy is set at
 * most once in each. Setting one inserts its row with insert-or-ignore against
 * the table's unique key, so setting a guardrail the scope already has,
 * including one a concurrent transaction has just set, never surfaces a
 * unique-constraint violation: the row is read back under a row lock and left
 * alone.
 *
 * An ignored insert is only ever reported once a row is read back: one that
 * leaves no row, as when a concurrent call removed it in between, is tried
 * again, and when that leaves none either, nothing is reported set. On MySQL
 * that is a policy deleted at the same moment, whose foreign key failure
 * `INSERT IGNORE` turns into a warning, so a guardrail is never reported, nor
 * its event dispatched, with no row to bear it out.
 *
 * Every row the writer inserts records the actor the call names in
 * `granted_by_type` and `granted_by_id`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GuardrailTable
{
    /**
     * Create a new guardrail table writer.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $grantedBy
     */
    public function __construct(

        /** The package connection the table lives on. */
        private Connection $connection,

        /** The guardrails table. */
        private string $table,

        /** The tenant the guardrails hold on; null for the platform. */
        private ?Reference $tenant = null,

        /** Who sets the guardrail, recorded on each row written; null for none. */
        private ?Reference $grantedBy = null,
    ) {}

    /**
     * Set the policy with the given key as a guardrail in the scope, and report
     * what changed: a new guardrail, nothing when the scope already had it, or
     * null when no row could be written, even once tried again, so nothing is
     * set.
     *
     * @param  string  $policy
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome|null
     */
    public function set(string $policy): ?GrantOutcome
    {
        // Once the insert is ignored, a locking read: on MySQL a plain read
        // would see the transaction's snapshot rather than the row it has just
        // locked. A row a concurrent call removed in between is set afresh.
        for ($attempt = 0; $attempt < 2; $attempt++) {
            if ($this->wasInserted($policy)) {
                return GrantOutcome::GRANTED;
            }

            if ($this->inScope($policy)->lockForUpdate()->exists()) {
                return GrantOutcome::UNCHANGED;
            }
        }

        return null;
    }

    /**
     * Remove the guardrail the policy with the given key is in the scope, and
     * report whether the scope had it.
     *
     * @param  string  $policy
     * @return bool
     */
    public function remove(string $policy): bool
    {
        return $this->inScope($policy)->delete() > 0;
    }

    /**
     * Insert the guardrail in the scope unless the scope has it, and report
     * whether it was inserted.
     *
     * @param  string  $policy
     * @return bool
     */
    private function wasInserted(string $policy): bool
    {
        $now = Carbon::now();

        return $this->connection->table($this->table)->insertOrIgnore([
            'policy_id'       => $policy,
            'tenant_type'     => $this->tenant?->type,
            'tenant_id'       => $this->tenant?->id,
            'granted_by_type' => $this->grantedBy?->type,
            'granted_by_id'   => $this->grantedBy?->id,
            'created_at'      => $now,
            'updated_at'      => $now,
        ]) === 1;
    }

    /**
     * Query the guardrail the policy with the given key is in the scope: on its
     * tenant, or platform-wide.
     *
     * @param  string  $policy
     * @return \Illuminate\Database\Query\Builder
     */
    private function inScope(string $policy): Builder
    {
        $query = $this->connection->table($this->table)->where('policy_id', $policy);

        if ($this->tenant === null) {
            return $query->whereNull('tenant_type')->whereNull('tenant_id');
        }

        return $query->where('tenant_type', $this->tenant->type)->where('tenant_id', $this->tenant->id);
    }
}
