<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Implemented by every event the package dispatches for a change to its stored
 * records: the role, permission and policy record events, the role permission
 * events, the grant, boundary, resource policy and guardrail events. The
 * decision events and `SystemOverrideUsed` do not implement it.
 *
 * An audit mapper typed against it reads what the change was, who it was about,
 * where it holds, whose access it changed, the rest of its details and the call
 * that made it, with its id, whether it was trusted, its actor, the identity
 * behind the actor, any impersonator and its time, through these accessors,
 * never through the event's properties.
 *
 * The call's client, its IP address and user agent, is deliberately absent: it
 * is personal data, carried to the grant hook alone (see
 * `Hooks\GrantWidening`), and no accessor, `auditProperties()` included,
 * reports it.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump, and each operation identifier is stable.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuthorizationMutation extends AuthorizationEvent
{
    /**
     * Return the stable identifier of the kind of change, such as
     * `identity.role.assigned`, one per event class.
     *
     * @return string
     */
    public function operation(): string;

    /**
     * Return the id of the call that made the change: the correlation id shared
     * by every event the call dispatched and every decision made for it.
     *
     * @return string
     */
    public function operationId(): string;

    /**
     * Determine whether the call was trusted system work, made without an
     * acting context, so nothing was decided for it.
     *
     * @return bool
     */
    public function isTrusted(): bool;

    /**
     * Return who made the call: the acting subject's principal, the reference a
     * trusted command names, or null for system work.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    public function actor(): ?Reference;

    /**
     * Return the identity behind the acting principal; null for none or a
     * trusted call.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    public function actorIdentity(): ?Reference;

    /**
     * Return who was impersonating the acting subject; null when no one was.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    public function impersonator(): ?Reference;

    /**
     * Return when the call was made, in UTC.
     *
     * @return \DateTimeImmutable
     */
    public function occurredAt(): \DateTimeImmutable;

    /**
     * Return the record the change is about: the grantee whose grants changed,
     * the role, permission or policy written, the resource whose policies
     * changed or the tenant whose guardrails changed; null when there is none,
     * for a whole resource type or the platform.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    public function subject(): ?Reference;

    /**
     * Return the tenant the change holds in, or the tenant that owns the record
     * changed; null for the platform.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    public function tenant(): ?Reference;

    /**
     * Return the application the change holds in; null for every application.
     *
     * @return string|null
     */
    public function application(): ?string;

    /**
     * Return every grantee whose access the change altered, a role included
     * when it gained or lost a permission; empty when the change names none.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    public function grantees(): array;

    /**
     * Return the event's other details, flat and serialisable: every property
     * but the operation, whose call the accessors above return without its
     * client, and the grantee, the grantees and the tenant, which the other
     * accessors return, keyed in snake case, a nested value under a dotted key,
     * a reference as `type:id` and a date as an ISO 8601 string in UTC.
     *
     * @return array<string, list<scalar>|scalar|null>
     */
    public function auditProperties(): array;
}
