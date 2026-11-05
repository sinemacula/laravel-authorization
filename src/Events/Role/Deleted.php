<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Role;

use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Dispatched once a role is deleted, and with it every grant of it and every
 * permission it carried.
 *
 * `grantees` lists every grantee that held the role, in any scope and whether
 * or not the grant had expired, and `permissions` every permission the role
 * carried, each read inside the delete's transaction before the row was
 * removed, so the evidence says who lost access and to what. A role's children
 * are not listed.
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
final readonly class Deleted implements AuthorizationEvent
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $role
     * @param  string  $name
     * @param  string|null  $guard
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $grantees
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $permissions
     */
    public function __construct(

        /** The call that made the change: its id, actor and time. */
        public Operation $operation,

        /** The role. */
        public Reference $role,

        /** The role's name. */
        public string $name,

        /** The guard the role belongs to; null for every guard. */
        public ?string $guard,

        /** The tenant that owns the role; null for the platform. */
        public ?Reference $tenant,

        /** Every grantee that held the role. */
        public array $grantees,

        /** Every permission the role carried. */
        public array $permissions,
    ) {}
}
