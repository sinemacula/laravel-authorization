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
 * Dispatched when a grant or sync rewrites the expiry of a role the grantee
 * holds: a live grant given another expiry, or an expired grant re-armed.
 *
 * The grant service dispatches it alongside `RoleAssigned`, so a listener can
 * record the expiry change as its own row. Without it, granting a forever role
 * again with an expiry would shorten it (or extend an expiring role to forever)
 * with no trail.
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
final readonly class RoleExpiryChanged implements IdentityEvent
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
     * @param  \DateTimeImmutable|null  $previousExpiresAt
     * @param  \DateTimeImmutable|null  $expiresAt
     */
    public function __construct(

        /** The call that made the change: its id, actor and time. */
        public Operation $operation,

        /** The grantee whose grant changed. */
        public Reference $grantee,

        /** The role whose grant was re-dated. */
        public Reference $role,

        /** The role's name. */
        public string $name,

        /** Where the grant holds: its tenant and application. */
        public GrantScope $scope,

        /** The expiry before the write, in UTC; null for forever. */
        public ?\DateTimeImmutable $previousExpiresAt,

        /** The expiry after the write, in UTC; null for forever. */
        public ?\DateTimeImmutable $expiresAt,
    ) {}

    /**
     * Return the stable identifier of the change:
     * `identity.role.expiry_changed`.
     *
     * @return string
     */
    #[\Override]
    public function operation(): string
    {
        return MutationOperation::IDENTITY_ROLE_EXPIRY_CHANGED->value;
    }
}
