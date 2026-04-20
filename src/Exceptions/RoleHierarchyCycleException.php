<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a proposed parent assignment would create a cycle in the role
 * hierarchy.
 *
 * Cycles are detected on write (the `saving` hook) and on read (the
 * `ancestors()` walk). The exception carries both role names so audit and error
 * reporting can identify the offending pair.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class RoleHierarchyCycleException extends \LogicException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $roleName
     * @param  string  $proposedParentName
     */
    public function __construct(

        /** Name of the role being assigned a parent. */
        private readonly string $roleName,

        /** Name of the proposed parent that would form a cycle. */
        private readonly string $proposedParentName,

    ) {
        parent::__construct(
            "Cannot set '{$proposedParentName}' as parent of '{$roleName}'"
                . ' — this would create a cycle in the role hierarchy.',
        );
    }

    /**
     * Return the role name that triggered the cycle detection.
     *
     * @return string
     */
    public function getRoleName(): string
    {
        return $this->roleName;
    }

    /**
     * Return the proposed parent name that would form a cycle.
     *
     * @return string
     */
    public function getProposedParentName(): string
    {
        return $this->proposedParentName;
    }
}
