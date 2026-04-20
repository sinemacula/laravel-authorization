<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console\Support;

use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * Result of comparing enum-derived permission tuples against the current DB
 * projection.
 *
 * The diff is a plain, immutable data bag. Every bucket is a list; the `update`
 * and `reinstate` buckets pair the existing row with the tuple that describes
 * its desired post-sync shape so the caller can apply the change without
 * re-walking the enum.
 *
 * `protected` rows are reported for visibility but are never mutated by sync;
 * `unchanged` rows are surfaced so `--dry-run` can claim zero drift against a
 * full count.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionDiff
{
    /**
     * Create a new permission diff.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Console\Support\PermissionTuple>  $add
     * @param  list<array{row: \SineMacula\Laravel\Authorization\Models\Permission, tuple: \SineMacula\Laravel\Authorization\Console\Support\PermissionTuple}>  $update
     * @param  list<array{row: \SineMacula\Laravel\Authorization\Models\Permission, tuple: \SineMacula\Laravel\Authorization\Console\Support\PermissionTuple}>  $reinstate
     * @param  list<\SineMacula\Laravel\Authorization\Models\Permission>  $retire
     * @param  list<\SineMacula\Laravel\Authorization\Models\Permission>  $protected
     * @param  list<\SineMacula\Laravel\Authorization\Models\Permission>  $unchanged
     * @param  int  $roleReferencesCount
     */
    public function __construct(

        /** Tuples with no matching DB row — candidates for INSERT. */
        public array $add,

        /** Rows whose metadata drifts from the enum tuple — candidates for UPDATE. */
        public array $update,

        /** Deprecated rows matched by a tuple — candidates for clear + refresh. */
        public array $reinstate,

        /** Rows with no matching tuple, `is_system = false` — candidates for deprecation. */
        public array $retire,

        /** Rows with no matching tuple, `is_system = true` — reported only, never touched. */
        public array $protected,

        /** Rows matched by a tuple whose metadata is identical and are not deprecated. */
        public array $unchanged,

        /** Pre-computed pivot count across all retire rows; reporting only. */
        public int $roleReferencesCount,

    ) {}
}
