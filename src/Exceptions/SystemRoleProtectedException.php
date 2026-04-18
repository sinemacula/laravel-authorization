<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a system-flagged role would be deleted or renamed
 * without the explicit `forceSystem()` escape hatch.
 *
 * Protects platform-shipped roles (`super-admin`, `auditor`,
 * `owner`) from accidental removal by a caller with raw Eloquent
 * access. The exception carries the role's current name so audit
 * and error reporting can identify the offending target.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class SystemRoleProtectedException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $roleName
     * @param  string  $operation
     */
    public function __construct(

        /** Name of the role whose mutation was refused. */
        private readonly string $roleName,

        /** Operation that was refused ("delete" or "rename"). */
        private readonly string $operation,

    ) {
        parent::__construct(
            "Refusing to {$operation} system role '{$roleName}'."
                . ' Call `forceSystem()` on the model before the operation to override.',
            403,
        );
    }

    /**
     * Return the role name that triggered the protection.
     *
     * @return string
     */
    public function getRoleName(): string
    {
        return $this->roleName;
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
