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
 * Dispatched when a break-glass activation grants a grantee an emergency role
 * (AUTHZ-11.7). The operation's actor is the granter, or no one for a trusted
 * call. The activation's note is never carried.
 *
 * A snapshot of plain values (references, the name, the scope, the key, the
 * code and times), never a model. It is dispatched once the write commits, on
 * the package's connection, and never for a write that rolls back.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class BreakGlassActivated implements IdentityEvent
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
     * @param  string  $justification
     * @param  \DateTimeImmutable  $expiresAt
     */
    public function __construct(

        /** The call that made the activation: its id, actor and time. */
        public Operation $operation,

        /** The grantee the role was activated for. */
        public Reference $grantee,

        /** The emergency role activated. */
        public Reference $role,

        /** The role's name. */
        public string $name,

        /** Where the activation holds: its tenant and application. */
        public GrantScope $scope,

        /** The activation's key, a UUID. */
        public string $activation,

        /** The justification code given. */
        public string $justification,

        /** When the activation expires, in UTC. */
        public \DateTimeImmutable $expiresAt,
    ) {}

    /**
     * Return the stable identifier of the change:
     * `identity.break_glass.activated`.
     *
     * @return string
     */
    #[\Override]
    public function operation(): string
    {
        return MutationOperation::IDENTITY_BREAK_GLASS_ACTIVATED->value;
    }
}
