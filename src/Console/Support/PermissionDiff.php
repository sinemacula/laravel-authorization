<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console\Support;

/**
 * The difference between the declared permission catalogue and the platform's
 * permission rows.
 *
 * Every declared permission and every platform row lands in exactly one list:
 *
 * - `add`: declared, with no row.
 * - `update`: declared, with a row whose description or category differs.
 * - `stale`: a row no enum or provider declares, not marked system; reported,
 *   and deleted only when the sync prunes.
 * - `protected`: a system row that is stale, or that is declared with a
 *   different description or category; reported and never changed, since a
 *   system row refuses every edit.
 * - `unchanged`: declared, with a row that already matches.
 *
 * Each list is ordered by name, then guard, guard-agnostic first.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionDiff
{
    /**
     * Create a new permission diff.
     *
     * @formatter:off
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>  $add
     * @param  list<array{row: \SineMacula\Laravel\Authorization\Models\Permission, definition: \SineMacula\Laravel\Authorization\Support\PermissionDefinition}>  $update
     * @param  list<\SineMacula\Laravel\Authorization\Models\Permission>  $stale
     * @param  list<\SineMacula\Laravel\Authorization\Models\Permission>  $protected
     * @param  list<\SineMacula\Laravel\Authorization\Models\Permission>  $unchanged
     *
     * @formatter:on
     */
    public function __construct(

        /** Declared permissions with no row, to insert. */
        public array $add,

        /** Rows whose description or category differs, with their definition. */
        public array $update,

        /** Undeclared rows not marked system, deleted only when pruning. */
        public array $stale,

        /** System rows the sync would otherwise delete or edit; never changed. */
        public array $protected,

        /** Declared permissions whose row already matches. */
        public array $unchanged,
    ) {}
}
