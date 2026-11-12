<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Concerns;

use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The audit accessors every change event shares for the call that made the
 * change, read from the event's operation: its id, whether it was trusted, its
 * actor, the identity behind the actor, any impersonator and when it was made.
 *
 * The call's client, its IP address and user agent, is personal data carried to
 * the grant hook alone, so no accessor reports it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation
 */
trait DescribesOperation
{
    /**
     * Return the id of the call that made the change, shared by every event it
     * dispatched.
     *
     * @return string
     */
    #[\Override]
    public function operationId(): string
    {
        return $this->operation->id;
    }

    /**
     * Determine whether the call was trusted system work, made without an
     * acting context.
     *
     * @return bool
     */
    #[\Override]
    public function isTrusted(): bool
    {
        return $this->operation->isTrusted;
    }

    /**
     * Return who made the call: the acting subject's principal, the reference a
     * trusted command names, or null for system work.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    public function actor(): ?Reference
    {
        return $this->operation->actor;
    }

    /**
     * Return the identity behind the acting principal; null for none or a
     * trusted call.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    public function actorIdentity(): ?Reference
    {
        return $this->operation->identity;
    }

    /**
     * Return who was impersonating the acting subject; null when no one was.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    public function impersonator(): ?Reference
    {
        return $this->operation->impersonator;
    }

    /**
     * Return when the call was made, in UTC.
     *
     * @return \DateTimeImmutable
     */
    #[\Override]
    public function occurredAt(): \DateTimeImmutable
    {
        return $this->operation->at->setTimezone(new \DateTimeZone('UTC'));
    }
}
