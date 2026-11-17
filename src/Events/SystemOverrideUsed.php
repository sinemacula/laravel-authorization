<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Dispatched once a change to a system role, permission or policy that
 * `forceSystem()` unlocked has been written.
 *
 * A system record cannot be renamed, edited, deleted or have its system flag
 * cleared, nor a system role have its permissions or policies changed, except
 * through this explicit override, and each use of it is reported.
 * `protectedOperation` names the change the override allowed: `delete`,
 * `unprotect`, `rename`, `document-rewrite` or `modify`, or, for a role's
 * grants, the kind changed, such as `permission-change` or `policy-change`, or
 * `revoke-all`. The events of the change (`Updated` or `Deleted`, or the grant
 * events) are dispatched as well, with the same operation.
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
final readonly class SystemOverrideUsed implements AuthorizationEvent
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $record
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string  $protectedOperation
     */
    public function __construct(

        /** The call that made the change: its id, actor and time. */
        public Operation $operation,

        /** The system role, permission or policy. */
        public Reference $record,

        /** The record's name before the change. */
        public string $name,

        /** The tenant that owns the record; null for the platform. */
        public ?Reference $tenant,

        /** The change the override allowed. */
        public string $protectedOperation,
    ) {}
}
