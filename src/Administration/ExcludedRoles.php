<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * The constraints of a pair of mutually exclusive roles declared or removed
 * (AUTHZ-11.8, N135), weighed by the administration stage once the owner rule
 * has passed (see `DefinitionConstraints`): the rank and administered-scope
 * rules the package applies to a role definition.
 *
 * A pair hands out nothing, so neither change needs the impact check, but each
 * changes what may be granted later, so neither only narrows:
 *
 * - **rank** (N76): both roles must be junior to the actor, ranked in the
 *   pair's owner, as a role whose rank changes must be (see
 *   `Impact::juniorRank()`), so an actor never constrains, or frees, a role
 *   senior to it; an unranked role is junior to everyone, and the more senior
 *   of the two ranks is the one weighed;
 * - **scope** (N79): a removal lifts the pair across the whole reach of its
 *   owner, the owner and every tenant below it in every application, or the
 *   platform for a platform pair, so the actor must administer it (see
 *   `AdministeredScope`), and, while impersonating, be allowed
 *   `authorization:administration.impersonated` across it too; a declaration
 *   only adds a constraint, and is decided at its node alone, as a guardrail
 *   set is.
 *
 * A change naming no other role, which the service never builds, is
 * `administration.unprovable`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExcludedRoles
{
    /**
     * Return the reason the first constraint that fails refuses the pair's
     * change, or null when every one holds.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \Illuminate\Database\Eloquent\Model|null  $excluded
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    public static function refusal(OperationResource $operation, Role $role, ?Model $excluded, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        if (!$excluded instanceof Role) {
            return DecisionReason::ADMINISTRATION_UNPROVABLE;
        }

        $lifted = $operation->action === PackagePermissions::ROLE_EXCLUSION_REMOVE ? self::lifted($operation, $resource, $checks) : null;

        return $lifted ?? Impact::juniorRank($operation, self::seniorRank($role, $excluded), $checks);
    }

    /**
     * Return why the actor may not lift the pair across its owner's whole
     * reach: `administration.impersonating` while impersonating without
     * `authorization:administration.impersonated` there, else
     * `administration.scope` when it does not administer it all; null when it
     * does.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function lifted(OperationResource $operation, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        $reach = Impact::reachOf($operation->tenant);

        $isImpersonationRefused = $operation->impersonator                                                               !== null
            && AdministeredScope::refusalOf(PackagePermissions::ADMINISTRATION_IMPERSONATED, $resource, $reach, $checks) !== null;

        return $isImpersonationRefused ? DecisionReason::ADMINISTRATION_IMPERSONATING : AdministeredScope::refusal($operation, $resource, $reach, $checks);
    }

    /**
     * Return the more senior of the two roles' ranks, the lower number, or null
     * when neither is ranked.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $excluded
     * @return int|null
     */
    private static function seniorRank(Role $role, Role $excluded): ?int
    {
        $ranks = \array_filter([$role->rank, $excluded->rank], static fn (?int $rank): bool => $rank !== null);

        return $ranks === [] ? null : \min($ranks);
    }
}
