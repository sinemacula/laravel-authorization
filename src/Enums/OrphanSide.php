<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Enums;

/**
 * Which side of a `role_permissions` pivot failed to resolve.
 *
 * Carried on `OrphanedRolePermissionException` so callers inspect the missing
 * parent with a type-checked value instead of comparing against a string
 * literal. Backed by strings so the exception message retains the
 * human-readable sentinel (`'role'` / `'permission'`) without extra mapping at
 * the throw site.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum OrphanSide: string
{
    /**
     * The role-side parent is missing.
     */
    case ROLE = 'role';

    /**
     * The permission-side parent is missing.
     */
    case PERMISSION = 'permission';
}
