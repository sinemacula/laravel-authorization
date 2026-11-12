<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Role;

use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Events\Concerns\DescribesRecordChange;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Dispatched once a permission is revoked from a role, once for each permission
 * a revocation by name or a sync removes.
 *
 * Distinct from `Identity\PermissionRevoked`, which reports a permission
 * revoked from a grantee directly.
 *
 * A snapshot of plain values, never a model. It is dispatched once the write
 * commits, on the package's connection, and never for a write that rolls back
 * or changes nothing.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionRevoked implements AuthorizationMutation
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
     */
    public function __construct(

        /** The call that made the change: its id, actor and time. */
        public Operation $operation,

        /** The role. */
        public Reference $role,

        /** The role's name. */
        public string $roleName,

        /** The permission revoked. */
        public Reference $permission,

        /** The permission's name. */
        public string $permissionName,

        /** The tenant that owns the role; null for the platform. */
        public ?Reference $tenant,
    ) {}

    /**
     * Return the stable identifier of the change: `role.permission.revoked`.
     *
     * @return string
     */
    #[\Override]
    public function operation(): string
    {
        return 'role.permission.revoked';
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
