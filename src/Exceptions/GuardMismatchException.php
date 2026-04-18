<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a role-to-permission attachment would pair two rows
 * scoped to different guards.
 *
 * Guard-agnostic rows (null `guard_name`) are compatible with every
 * guard, so they never trigger the mismatch. Two concrete guards
 * must be equal. The check runs from the pivot model's `saving`
 * hook so direct relation use (`$role->permissions()->attach(...)`,
 * `sync(...)`) is caught alongside the typed Role API.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class GuardMismatchException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $roleName
     * @param  string  $permissionName
     * @param  string  $roleGuard
     * @param  string  $permissionGuard
     */
    public function __construct(

        /** Role whose guard scope the attachment targeted. */
        private readonly string $roleName,

        /** Permission whose guard scope the attachment attempted to pair. */
        private readonly string $permissionName,

        /** Guard on the role side. */
        private readonly string $roleGuard,

        /** Guard on the permission side. */
        private readonly string $permissionGuard,

    ) {
        parent::__construct(
            "Guard mismatch: role '{$roleName}' (guard '{$roleGuard}') cannot carry"
                . " permission '{$permissionName}' (guard '{$permissionGuard}')."
                . ' Scope one side to null for a guard-agnostic attachment, or match the guards.',
            422,
        );
    }

    /**
     * Return the role name.
     *
     * @return string
     */
    public function getRoleName(): string
    {
        return $this->roleName;
    }

    /**
     * Return the permission name.
     *
     * @return string
     */
    public function getPermissionName(): string
    {
        return $this->permissionName;
    }

    /**
     * Return the role-side guard.
     *
     * @return string
     */
    public function getRoleGuard(): string
    {
        return $this->roleGuard;
    }

    /**
     * Return the permission-side guard.
     *
     * @return string
     */
    public function getPermissionGuard(): string
    {
        return $this->permissionGuard;
    }
}
