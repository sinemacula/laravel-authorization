<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Exceptions\OrphanedRolePermissionException;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * The permissions one role carries, read and written by the role service inside
 * its transaction.
 *
 * A new grant is attached through the role's relation, so the role permission
 * pivot's guard and owner parity holds, inside a savepoint, so a concurrent
 * duplicate rolls back only the attachment and the grant is read back instead.
 * A held grant is read under a row lock and its expiry compared. A permission
 * or a role that is gone, refused by the pivot or by the foreign key, attaches
 * nothing.
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
            return self::inserted(AuthorizationConnection::connection(), function () use ($id, $expiresAt): bool {
                $this->role->permissions()->attach($id, ['expires_at' => $expiresAt]);

                return true;
            });
        } catch (OrphanedRolePermissionException) {
            return false;
        }
    }

    /**
     * Read the expiry of the role's grant of the permission under a row lock,
     * or null when the role does not carry it.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantChange|null
     */
    #[\Override]
    protected function lockedRow(string $id): ?GrantChange
    {
        $row = $this->row($id)->lockForUpdate()->first(['expires_at']);

        return $row === null ? null : new GrantChange(GrantOutcome::UNCHANGED, UtcDateTime::toUtc($row->expires_at));
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
