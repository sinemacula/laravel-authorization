<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Guardrail;

use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Support\AuditProperties;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * What every change to a guardrail carries (AUTHZ-7.6): the operation, with the
 * actor that made the change, the policy, its name and the scope, as
 * `GuardrailSet` and `GuardrailRemoved` report them.
 *
 * A snapshot of plain values (references, the name and the scope), never a
 * model. It is dispatched once the write commits, on the package's connection,
 * and never for a write that rolls back or changes nothing. A guardrail on a
 * tenant holds in its subtree and in every application, so its scope always
 * reaches below and names no application.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract readonly class GuardrailEvent implements AuthorizationMutation
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $policy
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     */
    public function __construct(

        /** The call that made the change: its id, actor and time. */
        public Operation $operation,

        /** The policy set or removed as the guardrail. */
        public Reference $policy,

        /** The policy's name. */
        public string $name,

        /** Where the guardrail holds, or held: its tenant, or the platform. */
        public GrantScope $scope,
    ) {}

    /**
     * Return the tenant whose guardrails changed; null for the platform.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    public function subject(): ?Reference
    {
        return $this->scope->tenant;
    }

    /**
     * Return the tenant the guardrail holds in; null for the platform.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    public function tenant(): ?Reference
    {
        return $this->scope->tenant;
    }

    /**
     * Return no application: a guardrail holds in every application.
     *
     * @return string|null
     */
    #[\Override]
    public function application(): ?string
    {
        return null;
    }

    /**
     * Return no grantee: a guardrail names none.
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
