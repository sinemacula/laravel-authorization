<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Concerns;

use SineMacula\Laravel\Authorization\Support\AuditProperties;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The audit accessors of the grant and boundary events, each about one grantee
 * whose grants changed, in the scope the grant holds in: the grantee is the
 * subject and the one grantee, and the scope's tenant and application are where
 * the change holds.
 *
 * Each event using it names its own operation identifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation
 */
trait DescribesGrantChange
{
    /**
     * Return the grantee whose grants changed.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    #[\Override]
    public function subject(): Reference
    {
        return $this->grantee;
    }

    /**
     * Return the tenant the grant holds in; null for platform-wide.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    public function tenant(): ?Reference
    {
        return $this->scope->tenant;
    }

    /**
     * Return the application the grant holds in; null for every application.
     *
     * @return string|null
     */
    #[\Override]
    public function application(): ?string
    {
        return $this->scope->application;
    }

    /**
     * Return the grantee whose grants changed, alone.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    #[\Override]
    public function grantees(): array
    {
        return [$this->grantee];
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
