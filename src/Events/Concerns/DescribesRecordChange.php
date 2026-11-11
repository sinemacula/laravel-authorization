<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Concerns;

use SineMacula\Laravel\Authorization\Support\AuditProperties;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The audit accessors the role, permission and policy record events and the
 * role permission events share: the change holds where the record's owning
 * tenant is, in no one application, and names no grantee unless the event says
 * otherwise.
 *
 * Each event using it names its own operation identifier and subject, and an
 * event whose change altered someone's access names its grantees.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation
 */
trait DescribesRecordChange
{
    /**
     * Return the tenant that owns the record; null for the platform.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    public function tenant(): ?Reference
    {
        return $this->tenant;
    }

    /**
     * Return no application: a role, permission or policy belongs to none.
     *
     * @return string|null
     */
    #[\Override]
    public function application(): ?string
    {
        return null;
    }

    /**
     * Return no grantee: the event names none.
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
