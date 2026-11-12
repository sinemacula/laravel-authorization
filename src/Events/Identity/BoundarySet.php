<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Identity;

use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Dispatched when a policy is set as a grantee's permission boundary in a scope
 * (AUTHZ-7.4): a new boundary, one that replaces another policy there, or the
 * same boundary with a new reach.
 *
 * It carries what every change to a boundary does (see `BoundaryEvent`), and
 * the policy it replaced, when it replaced another.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class BoundarySet extends BoundaryEvent
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $policy
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $previous
     */
    public function __construct(

        // The call that made the change, handed to the parent event.
        Operation $operation,

        // The grantee whose boundary changed, handed to the parent event.
        Reference $grantee,

        // The policy set as the boundary, handed to the parent event.
        Reference $policy,

        // The policy's name, handed to the parent event.
        string $name,

        // Where the boundary holds, handed to the parent event.
        GrantScope $scope,

        /** The policy the boundary was before, when it was another; null otherwise. */
        public ?Reference $previous = null,
    ) {
        parent::__construct($operation, $grantee, $policy, $name, $scope);
    }

    /**
     * Return the stable identifier of the change: `identity.boundary.set`.
     *
     * @return string
     */
    #[\Override]
    public function operation(): string
    {
        return 'identity.boundary.set';
    }
}
