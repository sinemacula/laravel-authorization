<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a tenant's role would share its name with a platform system role
 * under a guard both answer.
 *
 * A check by role name, such as `hasRole('super-admin')`, the role middleware
 * or the Blade helpers, matches any held role of that name the tenant scope
 * shows. A tenant role named after a platform system role would therefore pass
 * every name check written for the system role. The role observer refuses the
 * tenant's row, and refuses a platform system role whose name a tenant already
 * owns, before either reaches the database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ReservedRoleNameException extends \LogicException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $roleName
     */
    public function __construct(

        /** Name of the role whose save was refused. */
        private readonly string $roleName,
    ) {
        parent::__construct(\sprintf(
            'Cannot save role \'%s\': a tenant role cannot share its name with a platform system role under a guard both answer.',
            $roleName,
        ));
    }

    /**
     * Return the name of the role whose save was refused.
     *
     * @return string
     */
    public function getRoleName(): string
    {
        return $this->roleName;
    }
}
