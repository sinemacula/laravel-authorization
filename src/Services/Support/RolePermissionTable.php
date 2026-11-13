<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Query\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * The permissions one role carries, read and written by the role service inside
 * its transaction.
 *
 * A new grant is attached through the role's relation, so the role permission
 * pivot's guard and owner parity holds, inside a savepoint, so a concurrent
 * duplicate rolls back only the attachment and the grant is read back instead.
 * A held grant is read under a row lock and its expiry compared.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RolePermissionTable extends ExpiringGrants
{
    /**
     * Create a new role permission writer.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     */
    public function __construct(

        /** The role whose permissions are written. */
        private Role $role,
    ) {}

    /**
     * Attach the permission unless the role carries it, expired or not, and
     * report whether it was attached.
     *
     * @param  string  $id
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @return bool
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function store(string $id, ?Carbon $expiresAt): bool
    {
        if ($this->row($id)->exists()) {
            return false;
        }

        $this->role->unsetRelation('permissions');

        try {
            AuthorizationConnection::connection()->transaction(fn () => $this->role->permissions()->attach($id, ['expires_at' => $expiresAt]));
        } catch (UniqueConstraintViolationException) {
            return false;
        }

        return true;
    }

    /**
     * Read the expiry of the role's grant of the permission under a row lock.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantChange
     */
    #[\Override]
    protected function lockedRow(string $id): GrantChange
    {
        return new GrantChange(GrantOutcome::UNCHANGED, UtcDateTime::toUtc($this->row($id)->lockForUpdate()->sole(['expires_at'])->expires_at));
    }

    /**
     * Write the new expiry to the role's grant of the permission.
     *
     * @param  string  $id
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @return void
     */
    #[\Override]
    protected function writeExpiry(string $id, ?Carbon $expiresAt): void
    {
        $this->row($id)->update(['expires_at' => $expiresAt]);
    }

    /**
     * Query the role's grant of the permission, expired or not.
     *
     * @param  string  $id
     * @return \Illuminate\Database\Query\Builder
     */
    private function row(string $id): Builder
    {
        return $this->role->permissions()->newPivotQuery()->where('permission_id', $id);
    }
}
