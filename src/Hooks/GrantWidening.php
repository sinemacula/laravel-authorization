<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Hooks;

use SineMacula\Laravel\Authorization\Enums\WideningReason;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * What a grant call proposes that widens an identity's scope, as the grant hook
 * is handed it (AUTHZ-11.3): the operation and who makes it, the identity whose
 * scope widens and the grantee the rows are written for, each grant that widens
 * it with its reasons, and when it was observed.
 *
 * The recipient identity and the grantee are told apart: a grant to the
 * identity itself names it as both, and a grant to one of its principals names
 * the principal as the grantee. Only the widening grants of the call are
 * listed; one that changes nothing, or only shortens what is held, is not.
 *
 * It is an immutable value of references, strings and immutable instants, with
 * no model and no mutable date, so a hook can neither change the grant through
 * it nor read more than the proposal says. An application calling the hook on
 * its own membership path (AUTHZ-13.9) builds one itself, with the reason
 * `WideningReason::MEMBERSHIP`.
 *
 * The client, the IP address and the user agent of the operation, is that of
 * the routed request a delegated call was made in, or what the caller passed
 * when it built the operation, and null for trusted, console and queued work
 * otherwise (see `Support\Operation`). Both are personal data: the package
 * hands them to the hook alone, never to an event, a cache key, a log or a
 * stored grant row, and a hook that keeps them is answerable for them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GrantWidening
{
    /** @var list<\SineMacula\Laravel\Authorization\Enums\WideningReason> Why the call widens the identity's scope: each reason of its grants once, in the order the reasons are declared. */
    public array $reasons;

    /**
     * Create a new widening.
     *
     * @param  string  $operationId
     * @param  bool  $isTrusted
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $actorIdentity
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $impersonator
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $identity
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  list<\SineMacula\Laravel\Authorization\Hooks\ProposedGrant>  $changes
     * @param  \DateTimeImmutable  $observedAt
     * @param  string|null  $ip
     * @param  string|null  $userAgent
     */
    public function __construct(

        /** The id of the operation the call runs as, shared by its decisions and events. */
        public string $operationId,

        /** Whether the call is trusted system work, made without an acting context (N75). */
        public bool $isTrusted,

        /** The acting principal, or the reference a trusted command names, or null for none. */
        public ?Reference $actor,

        /** The identity behind the acting principal, or null for none or a trusted call. */
        public ?Reference $actorIdentity,

        /** Who was impersonating the actor, or null when no one was. */
        public ?Reference $impersonator,

        /** The identity whose scope the grants widen. */
        public Reference $identity,

        /** The grantee the rows are written for: the identity itself or one of its principals. */
        public Reference $grantee,

        /** The grants of the call that widen the identity's scope, each with its reasons. */
        public array $changes,

        /** When the proposal was observed, in UTC. */
        public \DateTimeImmutable $observedAt,

        /** The IP address the operation came from, or null when unknown: personal data. */
        public ?string $ip = null,

        /** The user agent the operation came from, or null when unknown: personal data. */
        public ?string $userAgent = null,
    ) {
        $reasons = [];

        foreach ($changes as $change) {
            $reasons = [...$reasons, ...$change->reasons];
        }

        $this->reasons = \array_values(\array_filter(WideningReason::cases(), static fn (WideningReason $reason): bool => \in_array($reason, $reasons, true)));
    }

    /**
     * Return the widening of the grants the operation proposes for the grantee,
     * observed at the instant given, with the operation's client.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $identity
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  list<\SineMacula\Laravel\Authorization\Hooks\ProposedGrant>  $changes
     * @param  \DateTimeImmutable  $observedAt
     * @return self
     *
     * @internal
     */
    public static function of(Operation $operation, Reference $identity, Reference $grantee, array $changes, \DateTimeImmutable $observedAt): self
    {
        return new self(
            $operation->id,
            $operation->isTrusted,
            $operation->actor,
            $operation->identity,
            $operation->impersonator,
            $identity,
            $grantee,
            $changes,
            $observedAt,
            $operation->ip,
            $operation->userAgent,
        );
    }

    /**
     * Determine whether the grants are written for the identity itself, rather
     * than for one of its principals.
     *
     * @return bool
     */
    public function isToIdentity(): bool
    {
        return $this->grantee->type === $this->identity->type && $this->grantee->id === $this->identity->id;
    }
}
