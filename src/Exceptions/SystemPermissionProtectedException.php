<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a system-flagged permission would be deleted or
 * renamed without the explicit `forceSystem()` escape hatch.
 *
 * Protects platform-shipped permissions (e.g. `*:*`,
 * `system:audit`) from accidental removal by a caller with raw
 * Eloquent access. The exception carries the permission's current
 * name so audit and error reporting can identify the offending
 * target.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class SystemPermissionProtectedException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $permissionName
     * @param  string  $operation
     */
    public function __construct(

        /** Name of the permission whose mutation was refused. */
        private readonly string $permissionName,

        /** Operation that was refused ("delete" or "rename"). */
        private readonly string $operation,

    ) {
        parent::__construct(
            "Refusing to {$operation} system permission '{$permissionName}'."
                . ' Call `forceSystem()` on the model before the operation to override.',
            403,
        );
    }

    /**
     * Return the permission name that triggered the protection.
     *
     * @return string
     */
    public function getPermissionName(): string
    {
        return $this->permissionName;
    }

    /**
     * Return the operation that was refused.
     *
     * @return string
     */
    public function getOperation(): string
    {
        return $this->operation;
    }
}
