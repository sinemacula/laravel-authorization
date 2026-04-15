<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Permissions\Contracts;

/**
 * Permission enum contract.
 *
 * Defines the interface for permission enums. Each case represents
 * a discrete permission that can be checked via Laravel's Gate or
 * the permission manager. Implementing classes must be backed
 * enums.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface PermissionEnum extends \UnitEnum
{
    /**
     * Get the string representation of the permission.
     *
     * @return string
     */
    public function toString(): string;
}
