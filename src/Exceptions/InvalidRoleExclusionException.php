<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a role would be declared mutually exclusive with itself, or such
 * a pair removed or reported: a role excludes only another role (AUTHZ-11.8).
 *
 * The roles come from the calling code, so this is a programming error rather
 * than a client-facing outcome.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidRoleExclusionException extends \InvalidArgumentException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $role
     */
    public function __construct(

        /** The name of the role paired with itself. */
        private readonly string $role,
    ) {
        parent::__construct("Role '{$role}' cannot be mutually exclusive with itself: a pair names two roles.");
    }

    /**
     * Return the name of the role paired with itself.
     *
     * @return string
     */
    public function getRole(): string
    {
        return $this->role;
    }
}
