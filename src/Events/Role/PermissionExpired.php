<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Role;

use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Events\Concerns\DescribesRecordChange;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Dispatched once `authorization:prune` removes a role's grant of a permission
 * whose expiry has passed. The grant stopped counting at its expiry; this
 * reports its removal, in an operation with no actor.
 *
 * Distinct from `Identity\PermissionExpired`, which reports the removal of an
 * expired permission granted to a grantee directly.
 *
 * A snapshot of plain values, never a model. It is dispatched once the removal
 * commits, on the package's connection.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionExpired implements AuthorizationMutation
{
    use DescribesRecordChange;

    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $role
     * @param  string  $roleName
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $permission
     * @param  string  $permissionName
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \DateTimeImmutable  $expiredAt
     */
    public function __construct(

        /** The call that made the change: its id, actor and time. */
        public Operation $operation,

        /** The role. */
        public Reference $role,

        /** The role's name. */
        public string $roleName,

        /** The permission whose grant expired. */
        public Reference $permission,

        /** The permission's name. */
        public string $permissionName,

        /** The tenant that owns the role; null for the platform. */
        public ?Reference $tenant,

        /** When the grant expired, in UTC. */
        public \DateTimeImmutable $expiredAt,
    ) {}

    /**
     * Return the stable identifier of the change: `role.permission.expired`.
     *
     * @return string
     */
    #[\Override]
    public function operation(): string
    {
        return 'role.permission.expired';
    }

    /**
     * Return the role the change is about.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    #[\Override]
    public function subject(): Reference
    {
        return $this->role;
    }

    /**
     * Return the role, whose permissions changed.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    #[\Override]
    public function grantees(): array
    {
        return [$this->role];
    }
}
