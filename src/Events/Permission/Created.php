<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Permission;

use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Enums\MutationOperation;
use SineMacula\Laravel\Authorization\Events\Concerns\DescribesRecordChange;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Dispatched once a permission is created.
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
final readonly class Created implements AuthorizationMutation
{
    use DescribesRecordChange;

    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $permission
     * @param  string  $name
     * @param  string|null  $guard
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $isSystem
     */
    public function __construct(

        /** The call that made the change: its id, actor and time. */
        public Operation $operation,

        /** The permission. */
        public Reference $permission,

        /** The permission's name. */
        public string $name,

        /** The guard the permission belongs to; null for every guard. */
        public ?string $guard,

        /** The tenant that owns the permission; null for the platform. */
        public ?Reference $tenant,

        /** Whether the permission is a system permission. */
        public bool $isSystem,
    ) {}

    /**
     * Return the stable identifier of the change: `permission.created`.
     *
     * @return string
     */
    #[\Override]
    public function operation(): string
    {
        return MutationOperation::PERMISSION_CREATED->value;
    }

    /**
     * Return the permission the change is about.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    #[\Override]
    public function subject(): Reference
    {
        return $this->permission;
    }
}
