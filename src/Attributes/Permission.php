<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Attributes;

/**
 * Per-case permission metadata attribute.
 *
 * Applied to `PermissionEnum` cases to carry the metadata the package syncs to
 * the `permissions` table: a human-readable description, a category for
 * admin-UI grouping, and the guards the permission applies to.
 *
 * `guards: null` or omitted yields a single guard-agnostic permission row
 * (`guard = null`). Supplying `['web', 'api']` produces one row per guard. An
 * empty array is invalid and raises a typed exception when the sync command
 * walks the attribute.
 *
 * Consumers alias the import because `Models\Permission` shares the unqualified
 * name:
 *
 * ```php
 * use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
 *
 * enum Permission: string implements PermissionEnum
 * {
 *     #[PermissionMeta(description: 'View applications', category: 'Applications')]
 *     case VIEW_APPLICATIONS = 'applications:view';
 * }
 * ```
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[\Attribute(\Attribute::TARGET_CLASS_CONSTANT)]
final readonly class Permission
{
    /**
     * Create a new permission metadata attribute.
     *
     * @param  string|null  $description
     * @param  string|null  $category
     * @param  list<string>|null  $guards
     */
    public function __construct(

        /** Human-readable description persisted to the `description` column. */
        public ?string $description = null,

        /** Admin-UI category persisted to the `category` column. */
        public ?string $category = null,

        /** Guards the permission applies to; null = guard-agnostic. */
        public ?array $guards = null,

    ) {}
}
