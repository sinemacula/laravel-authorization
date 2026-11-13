<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Identity;

use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Events\Concerns\DescribesGrantChange;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * What a break-glass activation ended before its expiry carries (AUTHZ-11.7),
 * as `BreakGlassSurrendered` and `BreakGlassRevoked` report it. The operation's
 * actor is the one who ended it, or no one for a trusted call. The activation's
 * note is never carried.
 *
 * A snapshot of plain values (references, the name, the scope, the key and
 * times), never a model. It is dispatched once the write commits, on the
 * package's connection, and never for a write that rolls back or changes
 * nothing.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract readonly class BreakGlassEnded implements IdentityEvent
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
     * @param  \DateTimeImmutable  $endedAt
     */
    public function __construct(

        /** The call that ended the activation: its id, actor and time. */
        public Operation $operation,

        /** The grantee whose activation ended. */
        public Reference $grantee,

        /** The emergency role the activation granted. */
        public Reference $role,

        /** The role's name. */
        public string $name,

        /** Where the activation held: its tenant and application. */
        public GrantScope $scope,

        /** The activation's key, a UUID. */
        public string $activation,

        /** When the activation ended, in UTC. */
        public \DateTimeImmutable $endedAt,
    ) {}
}
