<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a `RolePermission` pivot save references a role or
 * permission row that cannot be resolved.
 *
 * The pivot's guard-parity hook has to read both parents'
 * `guard_name` columns. If the caller attaches a pivot whose
 * `role_id` or `permission_id` points at a missing row (deleted
 * under the request, cross-tenant leak, stale ID cache), the
 * save surfaces this typed failure rather than silently passing
 * the guard check and deferring to the DB's FK constraint —
 * which is absent on SQLite by default and on any environment
 * running with `foreign_key_checks = OFF`. Callers get the
 * semantic reason ("orphaned parent") instead of a raw FK error.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class OrphanedRolePermissionException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $side
     * @param  string  $parentId
     */
    public function __construct(

        /** Which side is missing: "role" or "permission". */
        private readonly string $side,

        /** The ID that failed to resolve. */
        private readonly string $parentId,

    ) {
        parent::__construct(
            "Orphaned role_permissions pivot: {$side} '{$parentId}' does not exist."
                . ' Refusing to persist a pivot row with a missing parent.',
            422,
        );
    }

    /**
     * Return which side was missing ("role" or "permission").
     *
     * @return string
     */
    public function getSide(): string
    {
        return $this->side;
    }

    /**
     * Return the parent ID that failed to resolve.
     *
     * @return string
     */
    public function getParentId(): string
    {
        return $this->parentId;
    }
}
