<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Identity;

use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Enums\MutationOperation;
use SineMacula\Laravel\Authorization\Events\Concerns\DescribesGrantChange;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Dispatched when `authorization:prune` records the expiry of a break-glass
 * activation that expired without ending (AUTHZ-11.7).
 *
 * The activation stopped counting at its expiry, with no sweep needed; this
 * reports the expiry recorded on its row, which is kept. The operation names no
 * actor: the sweep is system work.
 *
 * A snapshot of plain values (references, the name, the scope, the key and
 * times), never a model. It is dispatched once the write commits, on the
 * package's connection, and never for a write that rolls back.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class BreakGlassExpired implements IdentityEvent
{
    use DescribesGrantChange;

    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $role
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  string  $activation
     * @param  \DateTimeImmutable  $expiredAt
     */
    public function __construct(

        /** The sweep that recorded the expiry: its id and time, with no actor. */
        public Operation $operation,

        /** The grantee whose activation expired. */
        public Reference $grantee,

        /** The emergency role the activation granted. */
        public Reference $role,

        /** The role's name. */
        public string $name,

        /** Where the activation held: its tenant and application. */
        public GrantScope $scope,

        /** The activation's key, a UUID. */
        public string $activation,

        /** When the activation expired, in UTC. */
        public \DateTimeImmutable $expiredAt,
    ) {}

    /**
     * Return the stable identifier of the change:
     * `identity.break_glass.expired`.
     *
     * @return string
     */
    #[\Override]
    public function operation(): string
    {
        return MutationOperation::IDENTITY_BREAK_GLASS_EXPIRED->value;
    }
}
