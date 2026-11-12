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
 * tenant's, so a platform role takes only the platform's. A role, permission or
 * parent naming half a tenant, a type without a key or a key without a type,
 * which the package never writes, is neither the platform's nor any tenant's,
 * so it is never linked, as it is never granted
 * (`InvalidTenantColumnsException`); a link with one already stored applies
 * nowhere, so it never keeps the guard of the other record from changing. Two
 * concrete guards must be equal; a guard-agnostic side is compatible with every
 * guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RoleParity
{
    /**
     * Refuse a permission the role cannot carry: one limited to another guard,
     * or one another tenant owns (`OwnerMismatchException`). Linking the two,
     * either naming half a tenant is refused (`InvalidTenantColumnsException`);
     * checking a link already stored, when the guard of either changes, a link
     * with such a record is passed over, since it applies nowhere and nothing
     * is linked.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @param  bool  $isLinking
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException
     */
    public static function assertCarries(Role $role, Permission $permission, bool $isLinking = true): void
    {
        $mismatch = static fn (): GuardMismatchException => new GuardMismatchException($role->name, $permission->name, (string) $role->guard, (string) $permission->guard);

        self::assertLinkable($role, $permission, 'permission', $isLinking, $mismatch);
    }

    /**
     * Refuse a parent the role cannot sit under: one limited to another guard,
     * or one another tenant owns (`OwnerMismatchException`). Linking the two,
     * either naming half a tenant is refused (`InvalidTenantColumnsException`);
     * checking a link already stored, when the guard of either changes, a link
     * with such a role is passed over, since it applies nowhere and nothing is
     * linked.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $parent
     * @param  bool  $isLinking
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\ParentGuardMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException
     */
    public static function assertUnder(Role $role, Role $parent, bool $isLinking = true): void
    {
        $mismatch = static fn (): ParentGuardMismatchException => new ParentGuardMismatchException($role->name, $parent->name, (string) $role->guard, (string) $parent->guard);

        self::assertLinkable($role, $parent, 'parent role', $isLinking, $mismatch);
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
     * Refuse a permission or parent of the kind the role cannot take: one
     * limited to another guard, with the exception the callback makes, or one
     * another tenant owns (`OwnerMismatchException`); one naming half a tenant
     * is refused when they are being linked, else passed over (see
     * `isWhole()`).
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|\SineMacula\Laravel\Authorization\Models\Role  $related
     * @param  string  $kind
     * @param  bool  $isLinking
     * @param  \Closure(): \Throwable  $mismatch
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException
     * @throws \Throwable
     */
    private static function assertLinkable(Role $role, Permission|Role $related, string $kind, bool $isLinking, \Closure $mismatch): void
    {
        if (!self::isWhole($role, $related, $kind, $isLinking)) {
            return;
        }

        if (!self::guardsMatch($role->guard, $related->guard)) {
            throw $mismatch();
        }

        $owners = self::foreignOwners($role, $related);

        if ($owners !== null) {
            throw new OwnerMismatchException($role->name, $owners[0], $kind, $related->name, $owners[1]);
        }
    }

    /**
     * Determine whether the role and the permission or parent it is linked to
     * each name a whole tenant, or none: when they are being linked, either
     * naming half a tenant is refused rather than taken as the platform's;
     * otherwise such a link is reported as not whole, to be passed over.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \Illuminate\Database\Eloquent\Model  $related
     * @param  string  $kind
     * @param  bool  $isLinking
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException
     */
    private static function isWhole(Role $role, Model $related, string $kind, bool $isLinking): bool
    {
        if ($isLinking) {
            RecordOwner::assertWhole($role, 'role', 'link');
            RecordOwner::assertWhole($related, $kind, 'link');
        }

        return !TenantColumns::isHalf($role->getAttribute('tenant_type'), $role->getAttribute('tenant_id'))
            && !TenantColumns::isHalf($related->getAttribute('tenant_type'), $related->getAttribute('tenant_id'));
    }

    /**
     * Return the owners of the role and of a permission or parent another
     * tenant owns, or null when the role may take it: the platform owns it, or
     * the role's own tenant or one of its ancestors does.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \Illuminate\Database\Eloquent\Model  $related
     * @return array{0: \SineMacula\Laravel\Authorization\Support\Reference|null, 1: \SineMacula\Laravel\Authorization\Support\Reference}|null
     */
    private static function foreignOwners(Role $role, Model $related): ?array
    {
        $owner        = Reference::tenantOf($role);
        $relatedOwner = Reference::tenantOf($related);

        if ($relatedOwner === null || TenantChain::isWithin($owner, $relatedOwner)) {
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
