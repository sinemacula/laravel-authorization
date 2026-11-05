<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a system-flagged policy would be deleted, edited or have its
 * system flag cleared without the explicit `forceSystem()` escape hatch.
 *
 * Protects platform-shipped policies (e.g. `break-glass`, `system-audit`) from
 * accidental removal or change by a caller with raw Eloquent access. The
 * exception carries the policy's persisted name, or its key when it was loaded
 * without one, so audit and error reporting can identify the offending target.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SystemPolicyProtectedException extends SystemRecordProtectedException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $policyName
     * @param  string  $operation
     */
    public function __construct(string $policyName, string $operation)
    {
        parent::__construct('policy', $policyName, $operation);
    }

    /**
     * Return the policy name that triggered the protection.
     *
     * @return string
     */
    public function getPolicyName(): string
    {
        return $this->getRecordName();
    }
}
