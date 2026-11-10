<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * Whether a delegated change of a role's parent hands out only what the actor
 * may hand out, to holders it administers (AUTHZ-3.3, AUTHZ-11.1), as the
 * administration stage weighs it for a role the actor's context owns (see
 * `DefinitionConstraints`).
 *
 * Every holder of the role, and of every role below it, gets the parent's whole
 * authority, its ancestors' included (see `RoleAuthority`), and loses the old
 * parent's:
 *
 * - keeping the same parent changes nothing;
 * - replacing or clearing a parent whose chain carries a deny, a policy that
 *   denies anything attached to it or to one of its ancestors (see
 *   `Narrowing`), lifts that deny for every holder, which cannot be bounded, so
 *   it is refused as `administration.unprovable`; clearing one that carries
 *   none only narrows;
 * - setting or replacing a parent needs the impact check over every holder (see
 *   `Impact`) and the permission and policy routes for the new parent's whole
 *   authority across the role's reach (see `Possession` and `PolicyRoute`); a
 *   chain that cannot be read whole is unprovable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RoleParent
{
    /**
     * Return why giving the role the parent with the key, or none, is refused,
     * or null when it is allowed.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  mixed  $parent
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    public static function refusal(OperationResource $operation, Role $role, mixed $parent, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        $new = \is_scalar($parent) && $parent !== '' ? (string) $parent : null;
        $old = $role->parent_id;

        if ($new === $old) {
            return null;
        }

        if ($old !== null && !self::isLiftable($old)) {
            return DecisionReason::ADMINISTRATION_UNPROVABLE;
        }

        return $new === null ? null : self::added($operation, $role, $new, $resource, $checks);
    }

    /**
     * Determine whether the role with the key, as the old parent, can be taken
     * out of a chain without lifting a deny: it exists and no policy attached
     * to it or to its ancestors denies anything.
     *
     * @param  string  $key
     * @return bool
     */
    private static function isLiftable(string $key): bool
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $class */
        $class  = ModelClasses::get('role');
        $parent = $class::query()->withoutGlobalScopes()->useWritePdo()->find($key);

        return $parent instanceof Role && Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $parent);
    }

    /**
     * Return why handing the new parent's whole authority to every holder of
     * the role, and of the roles below it, is refused, or null when it is
     * allowed.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  string  $parent
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function added(OperationResource $operation, Role $role, string $parent, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        $across    = DefinitionConstraints::across($operation, $role);
        $authority = RoleAuthority::of([$parent], $across->scope);

        if ($authority === null) {
            return DecisionReason::ADMINISTRATION_UNPROVABLE;
        }

        $route = static fn (): ?DecisionReason => $authority->refusal($operation, $across, $checks);

        return DefinitionConstraints::growth($operation, $resource, AffectedHolders::none()->ofRoles([$role->id]), $checks, $route);
    }
}
