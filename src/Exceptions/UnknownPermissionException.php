<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a permission assignment or revocation targets a permission that
 * does not exist.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UnknownPermissionException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $permission
     */
    public function __construct(

        /** Permission name that could not be resolved. */
        private readonly string $permission,
    ) {
        parent::__construct("Unknown permission '{$permission}'.", 404);
    }

    /**
     * Return the permission name that could not be resolved.
     *
     * @return string
     */
    public function getPermission(): string
    {
        return $this->permission;
    }
}
