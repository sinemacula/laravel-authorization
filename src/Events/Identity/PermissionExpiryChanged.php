<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Identity;

use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Dispatched when a grant or sync rewrites the expiry of a permission the
 * grantee holds directly: a live grant given another expiry, or an expired
 * grant re-armed. The grant service dispatches it alongside
 * `PermissionGranted`.
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
final readonly class PermissionExpiryChanged implements IdentityEvent
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $permission
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

        /** The permission whose grant was re-dated. */
        public Reference $permission,

        /** The permission's name. */
        public string $name,

        /** Where the grant holds: its tenant and application. */
        public GrantScope $scope,

        /** The expiry before the write, in UTC; null for forever. */
        public ?\DateTimeImmutable $previousExpiresAt,

        /** The expiry after the write, in UTC; null for forever. */
        public ?\DateTimeImmutable $expiresAt,
    ) {}
}
