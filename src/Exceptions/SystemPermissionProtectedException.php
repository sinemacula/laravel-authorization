<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a system-flagged permission would be deleted, edited or have its
 * system flag cleared without the explicit `forceSystem()` escape hatch.
 *
 * Protects platform-shipped permissions (e.g. `*`, `system:audit`) from
 * accidental removal or change by a caller with raw Eloquent access. The
 * exception carries the permission's persisted name, or its key when it was
 * loaded without one, so audit and error reporting can identify the offending
 * target.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SystemPermissionProtectedException extends SystemRecordProtectedException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $permissionName
     * @param  string  $operation
     */
    public function __construct(string $permissionName, string $operation)
    {
        parent::__construct('permission', $permissionName, $operation);
    }

    /**
     * Return the permission name that triggered the protection.
     *
     * @return string
     */
    public function getPermissionName(): string
    {
        return $this->getRecordName();
    }
}
