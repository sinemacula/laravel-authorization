<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Role;

use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Dispatched once a role is updated: renamed, described, re-parented, re-ranked
 * or otherwise changed.
 *
 * `changes` holds the fields the update changed: `before` their values before
 * it, `after` their values after it, as plain values (dates as ISO 8601 strings
 * in UTC). Both maps share the same keys. The name, guard and tenant are the
 * role's after the update.
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
final readonly class Updated implements AuthorizationEvent
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $role
     * @param  string  $name
     * @param  string|null  $guard
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  array{before: array<string, scalar|null>, after: array<string, scalar|null>}  $changes
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

        /** The changed fields, before and after the update. */
        public array $changes,
    ) {}
}
