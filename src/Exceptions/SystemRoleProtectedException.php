<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a system-flagged role would be deleted, edited or have its system
 * flag cleared without the explicit `forceSystem()` escape hatch.
 *
 * Protects platform-shipped roles (`super-admin`, `auditor`, `owner`) from
 * accidental removal or change by a caller with raw Eloquent access. The
 * exception carries the role's persisted name, or its key when it was loaded
 * without one, so audit and error reporting can identify the offending target.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SystemRoleProtectedException extends SystemRecordProtectedException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $roleName
     * @param  string  $operation
     */
    public function __construct(string $roleName, string $operation)
    {
        parent::__construct('role', $roleName, $operation);
    }

    /**
     * Return the role name that triggered the protection.
     *
     * @return string
     */
    public function getRoleName(): string
    {
        return $this->getRecordName();
    }
}
