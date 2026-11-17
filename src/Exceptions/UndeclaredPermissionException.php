<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a permission is created, renamed or granted under a name that
 * covers no declared permission (see `Support\DeclaredPermissions`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UndeclaredPermissionException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $permission
     */
    public function __construct(

        /** The permission name refused. */
        private readonly string $permission,
    ) {
        parent::__construct(
            "Permission '{$permission}' matches no declared permission; declare it in permission_enums or permission_providers.",
            422,
        );
    }

    /**
     * Return the permission name refused.
     *
     * @return string
     */
    public function getPermission(): string
    {
        return $this->permission;
    }
}
