<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a role would sit under a parent role limited to another guard.
 *
 * A guard-agnostic role (null `guard`) is compatible with every guard, so it
 * never triggers the mismatch on either side; two concrete guards must be
 * equal, as for a role and its permissions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ParentGuardMismatchException extends \InvalidArgumentException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $roleName
     * @param  string  $parentName
     * @param  string  $roleGuard
     * @param  string  $parentGuard
     */
    public function __construct(

        /** The child role's name. */
        private readonly string $roleName,

        /** The parent role's name. */
        private readonly string $parentName,

        /** The child role's guard. */
        private readonly string $roleGuard,

        /** The parent role's guard. */
        private readonly string $parentGuard,
    ) {
        parent::__construct(
            "Guard mismatch: role '{$roleName}' (guard '{$roleGuard}') cannot sit under parent role '{$parentName}' (guard '{$parentGuard}')."
                . ' Scope one side to null for a guard-agnostic link, or match the guards.',
        );
    }

    /**
     * Return the child role's name.
     *
     * @return string
     */
    public function getRoleName(): string
    {
        return $this->roleName;
    }

    /**
     * Return the parent role's name.
     *
     * @return string
     */
    public function getParentName(): string
    {
        return $this->parentName;
    }

    /**
     * Return the child role's guard.
     *
     * @return string
     */
    public function getRoleGuard(): string
    {
        return $this->roleGuard;
    }

    /**
     * Return the parent role's guard.
     *
     * @return string
     */
    public function getParentGuard(): string
    {
        return $this->parentGuard;
    }
}
