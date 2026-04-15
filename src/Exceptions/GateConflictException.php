<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown at boot when a permission enum case would overwrite an
 * existing Gate and the `authorization.gate.on_conflict` config entry
 * is set to `throw`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class GateConflictException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $permission
     */
    public function __construct(

        /** Permission whose Gate registration collided with an existing Gate. */
        private readonly string $permission,

    ) {
        parent::__construct(
            "Gate '{$permission}' is already registered and authorization.gate.on_conflict is set to 'throw'.",
        );
    }

    /**
     * Return the permission name whose Gate registration collided.
     *
     * @return string
     */
    public function getPermission(): string
    {
        return $this->permission;
    }
}
