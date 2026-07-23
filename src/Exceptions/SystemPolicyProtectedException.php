<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a system-flagged policy would be deleted or renamed without the
 * explicit `forceSystem()` escape hatch.
 *
 * Protects platform-shipped policies (e.g. `break-glass`, `system-audit`) from
 * accidental removal by a caller with raw Eloquent access. The exception
 * carries the policy's current name so audit and error reporting can identify
 * the offending target.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SystemPolicyProtectedException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $policyName
     * @param  string  $operation
     */
    public function __construct(

        /** Name of the policy whose mutation was refused. */
        private readonly string $policyName,

        /** Operation that was refused ("delete" or "rename"). */
        private readonly string $operation,
    ) {
        parent::__construct(
            "Refusing to {$operation} system policy '{$policyName}'."
                . ' Call `forceSystem()` on the model before the operation to override.',
            403,
        );
    }

    /**
     * Return the policy name that triggered the protection.
     *
     * @return string
     */
    public function getPolicyName(): string
    {
        return $this->policyName;
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
