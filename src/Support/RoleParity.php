<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Exceptions\GranteeGuardMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\ParentGuardMismatchException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Owner and guard parity between a role and what it takes: its permissions, its
 * parent, and the grantees it, or a permission, is granted to (AUTHZ-3.10,
 * AUTHZ-5.2).
 *
 * A role takes only the platform's permissions and parents and its own
 * tenant's, so a platform role takes only the platform's. Two concrete guards
 * must be equal; a guard-agnostic side is compatible with every guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RoleParity
{
    /**
     * Refuse a permission the role cannot carry: one limited to another guard,
     * or one another tenant owns (`OwnerMismatchException`).
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException
     */
    public static function assertCarries(Role $role, Permission $permission): void
    {
        if (!self::guardsMatch($role->guard, $permission->guard)) {
            throw new GuardMismatchException($role->name, $permission->name, (string) $role->guard, (string) $permission->guard);
        }

        $owners = self::foreignOwners($role, $permission);

        if ($owners !== null) {
            throw new OwnerMismatchException($role->name, $owners[0], 'permission', $permission->name, $owners[1]);
        }
    }

    /**
     * Refuse a parent the role cannot sit under: one limited to another guard,
     * or one another tenant owns (`OwnerMismatchException`).
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $parent
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\ParentGuardMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException
     */
    public static function assertUnder(Role $role, Role $parent): void
    {
        if (!self::guardsMatch($role->guard, $parent->guard)) {
            throw new ParentGuardMismatchException($role->name, $parent->name, (string) $role->guard, (string) $parent->guard);
        }

        $owners = self::foreignOwners($role, $parent);

        if ($owners !== null) {
            throw new OwnerMismatchException($role->name, $owners[0], 'parent role', $parent->name, $owners[1]);
        }
    }

    /**
     * Refuse a role or permission limited to a guard other than the one the
     * grantee declares.
     *
     * @param  string  $kind
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  string|null  $granteeGuard
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GranteeGuardMismatchException
     */
    public static function assertGrantable(string $kind, Model $target, ?string $granteeGuard): void
    {
        /** @var string|null $guard */
        $guard = $target->getAttribute('guard');

        if (self::guardsMatch($guard, $granteeGuard)) {
            return;
        }

        /** @var string $name */
        $name = $target->getAttribute('name');

        throw new GranteeGuardMismatchException($kind, $name, (string) $guard, (string) $granteeGuard);
    }

    /**
     * Return the owners of the role and of a permission or parent another
     * tenant owns, or null when the role may take it: the platform owns it, or
     * the role's own tenant does.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \Illuminate\Database\Eloquent\Model  $related
     * @return array{0: \SineMacula\Laravel\Authorization\Support\Reference|null, 1: \SineMacula\Laravel\Authorization\Support\Reference}|null
     */
    private static function foreignOwners(Role $role, Model $related): ?array
    {
        $owner        = Reference::tenantOf($role);
        $relatedOwner = Reference::tenantOf($related);

        if ($relatedOwner === null || ($owner?->type === $relatedOwner->type && $owner->id === $relatedOwner->id)) {
            return null;
        }

        return [$owner, $relatedOwner];
    }

    /**
     * Determine whether two guards are compatible: either is guard-agnostic, or
     * they are equal.
     *
     * @param  string|null  $left
     * @param  string|null  $right
     * @return bool
     */
    private static function guardsMatch(?string $left, ?string $right): bool
    {
        return $left === null || $right === null || $left === $right;
    }
}
