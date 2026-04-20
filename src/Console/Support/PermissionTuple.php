<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console\Support;

/**
 * Expected permission tuple derived from a `PermissionEnum` case and
 * its `#[Permission]` attribute.
 *
 * One tuple represents one target `(name, guard)` row in the
 * permissions table. A case with `guards: ['web', 'api']` expands into
 * two tuples; a case with `guards: null` yields a single tuple with
 * `guard = null` (guard-agnostic).
 *
 * The tuple is immutable and is the unit the diff engine keys its
 * matching on — equality against a DB row is `(name, guard)` only;
 * metadata drift is handled downstream.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionTuple
{
    /**
     * Create a new permission tuple.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @param  string|null  $description
     * @param  string|null  $category
     */
    public function __construct(

        /** Canonical permission name (the enum case's backing value). */
        public string $name,

        /** Guard the permission applies to; null = guard-agnostic. */
        public ?string $guard,

        /** Optional human-readable description from the attribute. */
        public ?string $description,

        /** Optional admin-UI category from the attribute. */
        public ?string $category,

    ) {}
}
