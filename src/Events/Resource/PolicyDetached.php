<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Resource;

use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Dispatched when a policy is detached from a resource, a record or a whole
 * resource type (AUTHZ-7.3), in one scope.
 *
 * A snapshot of plain values (references, the name and the scope), never a
 * model. It is dispatched once the write commits, on the package's connection,
 * and never for a write that rolls back or changes nothing.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PolicyDetached implements AuthorizationEvent
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  string  $resourceType
     * @param  string|null  $resourceId
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $policy
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     */
    public function __construct(

        /** The call that made the change: its id, actor and time. */
        public Operation $operation,

        /** The resource's type, its morph class. */
        public string $resourceType,

        /** The resource's key; null for the whole type. */
        public ?string $resourceId,

        /** The policy detached. */
        public Reference $policy,

        /** The policy's name. */
        public string $name,

        /** Where the attachment held: its tenant and application. */
        public GrantScope $scope,
    ) {}
}
