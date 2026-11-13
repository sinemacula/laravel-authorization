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
 * Dispatched when a permission is granted directly to a grantee, or a direct
 * grant of it that had expired is re-armed.
 *
 * Distinct from `Role\PermissionGranted`, which reports a permission granted to
 * a role.
 *
 * A snapshot of plain values (references, the name, the scope and times), never
 * a model. It is dispatched once the write commits, on the package's
 * connection, and never for a write that rolls back or changes nothing.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionGranted implements IdentityEvent
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
     * @param  \DateTimeImmutable|null  $expiresAt
     */
    public function __construct(

        /** The call that made the change: its id, actor and time. */
        public Operation $operation,

        /** The grantee whose grant changed. */
        public Reference $grantee,

        /** The permission granted. */
        public Reference $permission,

        /** The permission's name. */
        public string $name,

        /** Where the grant holds: its tenant and application. */
        public GrantScope $scope,

        /** When the grant expires, in UTC; null for a forever grant. */
        public ?\DateTimeImmutable $expiresAt,
    ) {}

    /**
     * Return the stable identifier of the change:
     * `identity.permission.granted`.
     *
     * @return string
     */
    #[\Override]
    public function operation(): string
    {
        return MutationOperation::IDENTITY_PERMISSION_GRANTED->value;
    }
}
