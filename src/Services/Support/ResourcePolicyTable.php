<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Support\GrantScope;

/**
 * The attachments of policies to one resource within one scope, read and
 * written by the resource policy service inside its transaction.
 *
 * The resource is a record of a type, or the whole type when its key is null.
 * The scope is a tenant, or the platform when it is null, and an application,
 * or every application when it is null. An attachment inserts its row with
 * insert-or-ignore against the table's unique key, so attaching a policy the
 * resource already holds in the scope, including one a concurrent transaction
 * has just attached, never surfaces a unique-constraint violation: it changes
 * the reach when that differs, read back under a row lock, and nothing
 * otherwise.
 *
 * An ignored insert is only ever reported once a row is read back: one that
 * leaves no row, as when a concurrent call detached it in between, is tried
 * again, and when that leaves none either, nothing is reported attached. On
 * MySQL that is a policy deleted at the same moment, whose foreign key failure
 * `INSERT IGNORE` turns into a warning, so an attachment is never reported, nor
 * its event dispatched, with no row to bear it out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ResourcePolicyTable
{
    /**
     * Create a new resource policy table writer.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  string  $resourceType
     * @param  string|null  $resourceId
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     */
    public function __construct(

        /** The package connection the table lives on. */
        private Connection $connection,

        /** The resource policies table. */
        private string $table,

        /** The resource's type, its morph class. */
        private string $resourceType,

        /** The resource's key; null for the whole type. */
        private ?string $resourceId,

        /** Where the attachments hold: the tenant, its reach and the application. */
        private GrantScope $scope,
    ) {}

    /**
     * Attach the policy with the given key in the scope, with the scope's
     * reach, and report what changed: a new attachment, its reach alone, or
     * nothing; null when no row could be written, even once tried again, so
     * nothing is attached.
     *
     * @param  string  $policy
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome|null
     */
    public function attach(string $policy): ?GrantOutcome
    {
        // Once the insert is ignored, a locking read: on MySQL a plain read
        // would see the transaction's snapshot rather than the row it has just
        // locked. A row a concurrent call detached in between is attached
        // afresh.
        for ($attempt = 0; $attempt < 2; $attempt++) {
            if ($this->wasInserted($policy)) {
                return GrantOutcome::GRANTED;
            }

            $reach = $this->inScope()->where('policy_id', $policy)->lockForUpdate()->value('include_subtree');

            if ($reach !== null) {
                return $this->withReach($policy, (bool) $reach);
            }
        }

        return null;
    }

    /**
     * Detach the policy with the given key in the scope, and return the scope
     * the attachment held in, with the reach it had, or null when the policy
     * was not attached in the scope.
     *
     * @param  string  $policy
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope|null
     */
    public function detach(string $policy): ?GrantScope
    {
        // A locking read, so the reach reported is the row's as it is deleted.
        $reach = $this->inScope()->where('policy_id', $policy)->lockForUpdate()->value('include_subtree');

        if ($reach === null) {
            return null;
        }

        $this->inScope()->where('policy_id', $policy)->delete();

        return new GrantScope($this->scope->tenant, $this->scope->application, (bool) $reach || $this->scope->tenant === null);
    }

    /**
     * Insert the attachment in the scope unless the resource holds it there,
     * and report whether it was inserted.
     *
     * @param  string  $policy
     * @return bool
     */
    private function wasInserted(string $policy): bool
    {
        $now = Carbon::now();

        return $this->connection->table($this->table)->insertOrIgnore([
            'policy_id'       => $policy,
            'resource_type'   => $this->resourceType,
            'resource_id'     => $this->resourceId,
            'tenant_type'     => $this->scope->tenant?->type,
            'tenant_id'       => $this->scope->tenant?->id,
            'include_subtree' => $this->scope->includeSubtree,
            'application'     => $this->scope->application,
            'created_at'      => $now,
            'updated_at'      => $now,
        ]) === 1;
    }

    /**
     * Give the attachment the resource holds in the scope, with the reach it
     * has, the scope's reach, and report whether that changed it.
     *
     * @param  string  $policy
     * @param  bool  $reach
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     */
    private function withReach(string $policy, bool $reach): GrantOutcome
    {
        if ($reach === $this->scope->includeSubtree) {
            return GrantOutcome::UNCHANGED;
        }

        $this->inScope()->where('policy_id', $policy)->update([
            'include_subtree' => $this->scope->includeSubtree,
            'updated_at'      => Carbon::now(),
        ]);

        return GrantOutcome::REACH_CHANGED;
    }

    /**
     * Query the resource's attachments in the scope: its tenant, or
     * platform-wide, and its application, or every application.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function inScope(): Builder
    {
        $query = $this->connection->table($this->table)->where('resource_type', $this->resourceType);
        $query = $this->resourceId         === null ? $query->whereNull('resource_id') : $query->where('resource_id', $this->resourceId);
        $query = $this->scope->application === null ? $query->whereNull('application') : $query->where('application', $this->scope->application);

        if ($this->scope->tenant === null) {
            return $query->whereNull('tenant_type')->whereNull('tenant_id');
        }

        return $query->where('tenant_type', $this->scope->tenant->type)->where('tenant_id', $this->scope->tenant->id);
    }
}
