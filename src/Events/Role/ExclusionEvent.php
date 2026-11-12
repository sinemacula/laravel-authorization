<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Role;

use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Events\Concerns\DescribesRecordChange;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * What every change to a pair of mutually exclusive roles carries (AUTHZ-11.8):
 * the operation, with the actor that made the change, the pair's two roles and
 * their names, the role with the lower key first, and the tenant that owns the
 * pair, as `ExclusionDeclared` and `ExclusionRemoved` report them.
 *
 * A snapshot of plain values (references and names), never a model. It is
 * dispatched once the write commits, on the package's connection, and never for
 * a write that rolls back or changes nothing. The change is about the pair's
 * first role, holds where the pair's owner is, in no one application, and names
 * no grantee: a pair hands out nothing.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract readonly class ExclusionEvent implements AuthorizationMutation
{
    use DescribesRecordChange;

    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $role
     * @param  string  $roleName
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $excludedRole
     * @param  string  $excludedRoleName
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     */
    public function __construct(

        /** The call that made the change: its id, actor and time. */
        public Operation $operation,

        /** The pair's first role, the one with the lower key. */
        public Reference $role,

        /** The first role's name. */
        public string $roleName,

        /** The pair's second role, the one with the higher key. */
        public Reference $excludedRole,

        /** The second role's name. */
        public string $excludedRoleName,

        /** The tenant that owns the pair; null for the platform. */
        public ?Reference $tenant,
    ) {}

    /**
     * Return the pair's first role, which the change is about.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    #[\Override]
    public function subject(): Reference
    {
        return $this->role;
    }
}
