<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Resource;

use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Support\AuditProperties;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * What every change to a resource policy attachment carries (AUTHZ-7.3): the
 * operation, the resource, a record or a whole resource type, the policy, its
 * name and the scope, as `PolicyAttached` and `PolicyDetached` report them.
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
abstract readonly class ResourcePolicyEvent implements AuthorizationMutation
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

        /** The policy attached or detached. */
        public Reference $policy,

        /** The policy's name. */
        public string $name,

        /** Where the attachment holds, or held: its tenant and application. */
        public GrantScope $scope,
    ) {}

    /**
     * Return the record whose policies changed; null for a whole resource type.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    public function subject(): ?Reference
    {
        return $this->resourceId === null ? null : new Reference($this->resourceType, $this->resourceId);
    }

    /**
     * Return the tenant the attachment holds in; null for platform-wide.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    public function tenant(): ?Reference
    {
        return $this->scope->tenant;
    }

    /**
     * Return the application the attachment holds in; null for every
     * application.
     *
     * @return string|null
     */
    #[\Override]
    public function application(): ?string
    {
        return $this->scope->application;
    }

    /**
     * Return no grantee: an attachment to a resource names none.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    #[\Override]
    public function grantees(): array
    {
        return [];
    }

    /**
     * Return the event's other details, flat and serialisable.
     *
     * @return array<string, list<scalar>|scalar|null>
     *
     * @throws \LogicException
     */
    #[\Override]
    public function auditProperties(): array
    {
        return AuditProperties::of($this);
    }
}
