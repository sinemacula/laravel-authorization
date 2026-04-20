<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a role assignment or revocation targets a role that does not
 * exist.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class UnknownRoleException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $role
     */
    public function __construct(

        /** Role name that could not be resolved. */
        private readonly string $role,

    ) {
        parent::__construct("Unknown role '{$role}'.", 404);
    }

    /**
     * Return the role name that could not be resolved.
     *
     * @return string
     */
    public function getRole(): string
    {
        return $this->role;
    }
}
