<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Database;

use Illuminate\Contracts\Database\Query\Builder;

/**
 * What the relation between a role and the permissions it carries reads, alike
 * from either side (`Role::permissions()` and `Permission::roles()`): the role
 * permission table `authorization.tables.role_permissions` names, and only the
 * rows whose grant has not expired. Each side binds the `RolePermission` pivot
 * and its `expires_at`, so every attachment through it, from either side, runs
 * through the pivot's `saving` hook and the guard-parity invariant it enforces.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RolePermissionRelation
{
    /**
     * Return the role permission table.
     *
     * @return string
     */
    public static function table(): string
    {
        /** @var string */
        return config('authorization.tables.role_permissions', 'role_permissions');
    }

    /**
     * Limit the relation's query to the rows of the role permission table whose
     * grant has not expired.
     *
     * @param  \Illuminate\Contracts\Database\Query\Builder  $query
     * @return void
     */
    public static function live(Builder $query): void
    {
        LiveGrants::only($query, self::table());
    }
}
