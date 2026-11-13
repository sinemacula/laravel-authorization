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
 * Dispatched when `authorization:prune` removes a permission grant that had
 * expired.
 *
 * The grant stopped counting at its expiry, with no sweep needed; this reports
 * its removal. The operation names no actor: the sweep is system work.
 *
 * A snapshot of plain values (references, the name, the scope and times), never
 * a model. It is dispatched once the write commits, on the package's
 * connection, and never for a write that rolls back.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionExpired implements IdentityEvent
{
    use DescribesGrantChange;

    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $permission
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  \DateTimeImmutable  $expiredAt
     */
    public function __construct(

        /** The sweep that removed the grant: its id and time, with no actor. */
        public Operation $operation,

        /** The grantee whose grant expired. */
        public Reference $grantee,

        /** The permission whose grant expired. */
        public Reference $permission,

        /** The permission's name. */
        public string $name,

        /** Where the grant held: its tenant and application. */
        public GrantScope $scope,

        /** When the grant expired, in UTC. */
        public \DateTimeImmutable $expiredAt,
    ) {}

    /**
     * Return the stable identifier of the change:
     * `identity.permission.expired`.
     *
     * @return string
     */
    #[\Override]
    public function operation(): string
    {
        return MutationOperation::IDENTITY_PERMISSION_EXPIRED->value;
    }
}
