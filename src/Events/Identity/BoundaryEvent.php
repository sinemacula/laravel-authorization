<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Identity;

use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * What every change to a grantee's permission boundary carries (AUTHZ-7.4): the
 * operation, the grantee, the policy, its name and the scope, as `BoundarySet`
 * and `BoundaryRemoved` report them.
 *
 * A snapshot of plain values (references, the name and the scope), never a
 * model. It is dispatched once the write commits, on the package's connection,
 * and never for a write that rolls back or changes nothing. A boundary holds in
 * every application, so its scope names none.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract readonly class BoundaryEvent implements IdentityEvent
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $policy
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     */
    public function __construct(

        /** The call that made the change: its id, actor and time. */
        public Operation $operation,

        /** The grantee whose boundary changed. */
        public Reference $grantee,

        /** The policy set or removed as the boundary. */
        public Reference $policy,

        /** The policy's name. */
        public string $name,

        /** Where the boundary holds, or held: its tenant and reach. */
        public GrantScope $scope,
    ) {}
}
