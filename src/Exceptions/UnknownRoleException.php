<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a role assignment or revocation targets a role that does not
 * exist.
 *
 * The name comes from the calling code, so this is a programming error rather
 * than a client-facing outcome, and it carries no HTTP-like status code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UnknownRoleException extends \RuntimeException
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
        parent::__construct("Unknown role '{$role}'.");
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
