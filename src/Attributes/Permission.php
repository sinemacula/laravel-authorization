<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Attributes;

/**
 * Catalogue metadata for a permission enum case.
 *
 * Placed on a case of a `PermissionEnum` to give the permission the case
 * declares a description and a category, which `authorization:sync` writes to
 * the permission's row, and the guards it applies to.
 *
 * `guards` left out, or null, declares one guard-agnostic permission (a null
 * `guard`). A list such as `['web', 'api']` declares one permission per guard.
 * An empty list declares nothing, so `authorization:sync` refuses it, as it
 * refuses a guard that is not a non-empty string.
 *
 * Applications usually alias the import, since the permission model shares the
 * unqualified name:
 *
 * ```php
 * use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
 *
 * enum ApplicationPermission: string implements PermissionEnum
 * {
 *     #[PermissionMeta(description: 'View applications', category: 'Applications')]
 *     case VIEW = 'applications:view';
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

        /** Human-readable description written to the `description` column. */
        public ?string $description = null,

        /** Grouping key for administration screens, written to `category`. */
        public ?string $category = null,

        /** Guards the permission applies to; null for one guard-agnostic row. */
        public ?array $guards = null,
    ) {}
}
