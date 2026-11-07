<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * The constraints of an operation on a shared definition (AUTHZ-11.1, D20, N78,
 * N79), weighed by the administration stage (see `OperationConstraints`): a
 * change to a role, a permission or a policy itself, a change to what a role
 * carries (its permissions and policies), and a policy's attachment to a
 * resource.
 *
 * 1. **Owner** (D20): a change to a definition, to a role's permissions or
 *    policies, or to a role's parent is made from the tenant that owns the
 *    definition, or the role, and a platform definition's from the platform:
 *    the tenant the check is made from (see `FurtherChecks`) must be the owner,
 *    or it is refused as `administration.owner`, whether or not it narrows (see
 *    `OwnerConstraint`). A definition being created is owned by the tenant its
 *    record names. A resource policy's attachment is a grant to a resource,
 *    which the rule never weighs (N79).
 * 2. A change that can only narrow is then allowed: removing a permission from
 *    a role, detaching an allow-only policy, one that changes nothing.
 * 3. Every other change is weighed by what it changes, each case below.
 *
 * - **Creating** a definition widens no one, so it passes, but a role created
 *   with a rank must be junior to the actor's (see `Impact::juniorRank()`).
 * - **Renaming a role**, and renaming a permission or changing its name or
 *   guard otherwise, changes what every existing grant means, so it is a new
 *   distribution to every holder: the impact check over them (see `Impact`),
 *   and, for a permission, the permission route under the new name across the
 *   definition's reach (see `Possession`).
 * - **Changing a role's rank** is made only to a role junior to the actor, so a
 *   senior role is never demoted, and must leave it junior to the actor; a rank
 *   made more senior is weighed by the impact check over the role's holders,
 *   the new rank counting as theirs. A rank that is no whole number, given as
 *   one or as its decimal text, cannot be compared, created or given, and is
 *   refused as `administration.rank_uncomparable`.
 * - **Deleting** a role narrows unless a policy attached to it, or to an
 *   ancestor, denies anything, deleting a permission always does, and deleting
 *   a policy does only when it has no deny statement (see `Narrowing`);
 *   anything else is `administration.unprovable`.
 * - **Rewriting a policy's document** changes nothing when the new document
 *   only narrows the old one, the same document in authority terms included
 *   (see `DocumentComparison`); one that lifts a deny is unprovable; one that
 *   adds allows is weighed by the impact check over every holder (the subjects
 *   it is attached to or bounds, the holders of every role it is attached to,
 *   and the principals its allows name where it is attached to a resource),
 *   needs the policy route for the allows it adds (see `PolicyRoute`), and, for
 *   a policy in use as a boundary, the further right
 *   `authorization:administration.unbounded`, as replacing a boundary with a
 *   wider one does (see `PolicyRewrite`). Describing or renaming a policy
 *   passes.
 * - **Adding a permission or attaching a policy to a role**, and **setting or
 *   replacing a role's parent**, hands what is added to every holder of the
 *   role and of every role below it: the impact check over them, and the
 *   permission or policy route for what is added, the new parent's whole
 *   authority with its ancestors' (see `RoleAuthority`), across the role's
 *   reach. A parent replaced or cleared whose chain carries a deny is
 *   unprovable, since lifting a deny cannot be bounded (see `RoleParent`).
 * - **Attaching a policy to a resource** hands its allows to every principal
 *   they name, and the holders of every role they name: the impact check over
 *   them across the attachment's reach, and the policy route. A role a selector
 *   names that no one holds yet is weighed when it is granted (see
 *   `RoleAuthority`).
 * - Anything else that may widen authority, a denying policy detached from a
 *   role or a resource included, is `administration.unprovable`.
 *
 * A change that reaches no holder widens no one, so it needs neither the impact
 * check nor a route.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DefinitionConstraints
{
    /** @var list<string> The actions of a resource policy's attachment, which the owner rule never weighs. */
    private const array RESOURCE_ACTIONS = [PackagePermissions::RESOURCE_POLICY_ATTACH, PackagePermissions::RESOURCE_POLICY_DETACH];

    /**
     * Return the reason the first constraint that fails refuses the operation,
     * or null when every one holds.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    public static function refusal(OperationResource $operation, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        if (!self::isOwnedHere($operation, $checks)) {
            return DecisionReason::ADMINISTRATION_OWNER;
        }

        return $operation->isNarrowing ? null : self::widening($operation, $resource, $checks);
    }

    /**
     * Return why a change handing something out to the holders is refused: the
     * impact check over them across the change's reach, the definition's when
     * none is given, then the route for what it hands out; null when it reaches
     * no holder or both hold.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\AffectedHolders  $affected
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @param  \Closure(): (\SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null)  $route
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange|null  $change
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    public static function growth(
        OperationResource $operation,
        ResourceReference $resource,
        AffectedHolders $affected,
        FurtherChecks $checks,
        \Closure $route,
        ?OperationChange $change = null,
    ): ?DecisionReason {
        $holders = $affected->holders();

        if ($holders === []) {
            return null;
        }

        $reach = $change->scope ?? Impact::reachOf($operation->tenant);

        return Impact::refusal($operation, $resource, $reach, $holders, $checks) ?? $route();
    }

    /**
     * Return the change a route for a definition is weighed across: the
     * definition handed out across every grant its owner allows, forever.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \Illuminate\Database\Eloquent\Model  $record
     * @return \SineMacula\Laravel\Authorization\Administration\OperationChange
     */
    public static function across(OperationResource $operation, Model $record): OperationChange
    {
        return new OperationChange(Reference::of($record), $record, Impact::reachOf($operation->tenant));
    }

    /**
     * Determine whether the change is made from the tenant that owns what it
     * edits: the definition, or the role whose permissions, policies or parent
     * it changes; a resource policy's attachment always is.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return bool
     */
    private static function isOwnedHere(OperationResource $operation, FurtherChecks $checks): bool
    {
        if (\in_array($operation->action, self::RESOURCE_ACTIONS, true)) {
            return true;
        }

        $role = $operation->change === null ? null : self::roleOf($operation->change);

        return ($operation->change === null || $role !== null) && OwnerConstraint::isOwner($role === null ? $operation->tenant : Reference::tenantOf($role), $checks->from);
    }

    /**
     * Return why a change that may widen authority is refused, by what it
     * changes, or null when it is allowed.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function widening(OperationResource $operation, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        $definition = $operation->definition;
        $change     = $operation->change;

        return match (true) {
            $definition !== null => self::ofDefinition($operation, $definition, $resource, $checks),
            $change     !== null => self::ofMembership($operation, $change, $resource, $checks),
            default              => DecisionReason::ADMINISTRATION_UNPROVABLE,
        };
    }

    /**
     * Return why a change to a role, a permission or a policy itself is
     * refused, by the kind of record it changes, or null when it is allowed.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\DefinitionChange  $definition
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function ofDefinition(OperationResource $operation, DefinitionChange $definition, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        $record = $definition->record;

        return match (true) {
            $record instanceof Role       => self::ofRole($operation, $record, $definition->values, $resource, $checks),
            $record instanceof Permission => self::ofPermission($operation, $definition, $record, $resource, $checks),
            $record instanceof Policy     => self::ofPolicy($operation, $definition, $record, $resource, $checks),
            default                       => DecisionReason::ADMINISTRATION_UNPROVABLE,
        };
    }

    /**
     * Return why a change to the role itself is refused, or null when it is
     * allowed.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  array<string, bool|float|int|string|null>  $values
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function ofRole(OperationResource $operation, Role $role, array $values, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        return match ($operation->action) {
            PackagePermissions::ROLE_CREATE     => self::createdRank($operation, self::rankOf($values), $checks),
            PackagePermissions::ROLE_RENAME     => self::reaching($operation, $resource, AffectedHolders::none()->ofRoles([$role->id]), $checks),
            PackagePermissions::ROLE_UPDATE     => self::ranked($operation, $role, $values, $resource, $checks),
            PackagePermissions::ROLE_DELETE     => self::unlessWidening(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $role)),
            PackagePermissions::ROLE_PARENT_SET => RoleParent::refusal($operation, $role, $values['parent'] ?? null, $resource, $checks),
            default                             => DecisionReason::ADMINISTRATION_UNPROVABLE,
        };
    }

    /**
     * Return why creating a role of the rank is refused: a rank that cannot be
     * read as a whole number cannot be compared, and one that can must be
     * junior to the actor's.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  false|int|null  $rank
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function createdRank(OperationResource $operation, false|int|null $rank, FurtherChecks $checks): ?DecisionReason
    {
        return $rank === false ? DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE : Impact::juniorRank($operation, $rank, $checks);
    }

    /**
     * Return why updating the role with the values is refused: a rank that
     * cannot be read as a whole number cannot be compared; a rank change is
     * made only to a role junior to the actor, so a senior role is never
     * demoted, and must leave it junior to the actor; and a rank more senior
     * than the role's is weighed by the impact check over the role's holders,
     * the rank counting as theirs. Any other update widens no one.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  array<string, bool|float|int|string|null>  $values
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function ranked(OperationResource $operation, Role $role, array $values, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        if (!\array_key_exists('rank', $values)) {
            return null;
        }

        $rank = self::rankOf($values);

        if ($rank === false) {
            return DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE;
        }

        $isMoreSenior = $rank !== null && $rank < ($role->rank ?? \PHP_INT_MAX);
        $holders      = $isMoreSenior ? AffectedHolders::none()->ofRoles([$role->id])->holders() : [];
        $reach        = Impact::reachOf($operation->tenant);

        return Impact::juniorRank($operation, $role->rank, $checks)
            ?? Impact::juniorRank($operation, $rank, $checks)
            ?? Impact::refusal($operation, $resource, $reach, $holders, $checks, $rank);
    }

    /**
     * Return the rank the values propose: null for none, a whole number given
     * as one or as its decimal text, or false for anything else, a fraction, a
     * flag or text that is no whole number included, which cannot be compared.
     *
     * @param  array<string, bool|float|int|string|null>  $values
     * @return false|int|null
     */
    private static function rankOf(array $values): false|int|null
    {
        $rank = $values['rank'] ?? null;

        return match (true) {
            $rank === null, \is_int($rank) => $rank,
            \is_string($rank)              => \filter_var($rank, \FILTER_VALIDATE_INT),
            default                        => false,
        };
    }

    /**
     * Return `administration.unprovable` for a change that may widen, or null
     * for one that only narrows.
     *
     * @param  bool  $isNarrowing
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function unlessWidening(bool $isNarrowing): ?DecisionReason
    {
        return $isNarrowing ? null : DecisionReason::ADMINISTRATION_UNPROVABLE;
    }

    /**
     * Return why a change to the permission itself is refused: a new name or
     * guard is a new distribution to every holder, under the new name; or null
     * when it is allowed.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\DefinitionChange  $definition
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function ofPermission(
        OperationResource $operation,
        DefinitionChange $definition,
        Permission $permission,
        ResourceReference $resource,
        FurtherChecks $checks,
    ): ?DecisionReason {
        $isRename = \in_array($operation->action, [PackagePermissions::PERMISSION_RENAME, PackagePermissions::PERMISSION_UPDATE], true);
        $renames  = $isRename && ($definition->proposes('name') || $definition->proposes('guard'));

        if (!$renames) {
            return null;
        }

        $name  = $definition->values['name'] ?? $permission->name;
        $named = new Permission(['name' => \is_string($name) ? $name : '']);
        $route = static fn (): ?DecisionReason => Possession::refusal($operation, self::across($operation, $permission), $named, $checks);

        return self::growth($operation, $resource, AffectedHolders::none()->ofPermission($permission), $checks, $route);
    }

    /**
     * Return why a change to the policy itself is refused, or null when it is
     * allowed.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\DefinitionChange  $definition
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function ofPolicy(
        OperationResource $operation,
        DefinitionChange $definition,
        Policy $policy,
        ResourceReference $resource,
        FurtherChecks $checks,
    ): ?DecisionReason {
        $document = $definition->document;
        $rewrites = $document !== null || $definition->proposes('digest');

        return match ($operation->action) {
            PackagePermissions::POLICY_CREATE, PackagePermissions::POLICY_RENAME => null,
            PackagePermissions::POLICY_UPDATE                                    => $rewrites ? PolicyRewrite::refusal($operation, $policy, $document, $resource, $checks) : null,
            PackagePermissions::POLICY_DELETE                                    => self::unlessWidening(Narrowing::isAllowOnly($policy)),
            default                                                              => DecisionReason::ADMINISTRATION_UNPROVABLE,
        };
    }

    /**
     * Return why a change to what a role carries, or to what a resource has
     * attached, is refused, or null when it is allowed: adding a permission or
     * attaching a policy to a role reaches every holder of the role and of the
     * roles below it, attaching a policy to a resource every principal it
     * names.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function ofMembership(OperationResource $operation, OperationChange $change, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        $target = $change->target;
        $route  = match (true) {
            $target instanceof Permission => static fn (): ?DecisionReason => Possession::refusal($operation, $change, $target, $checks),
            $target instanceof Policy     => static fn (): ?DecisionReason => PolicyRoute::refusal($operation, $change, $target, $checks),
            default                       => null,
        };

        $action     = $operation->action;
        $permission = $action === PackagePermissions::PERMISSION_GRANT && $target instanceof Permission;
        $toRole     = $permission || ($action === PackagePermissions::POLICY_ATTACH && $target instanceof Policy);
        $toResource = $action === PackagePermissions::RESOURCE_POLICY_ATTACH && $target instanceof Policy;

        $holders = match (true) {
            $toRole     => self::holdersOfRole($change),
            $toResource => AffectedHolders::none()->ofPrincipals(DocumentComparison::read($target->document)),
            default     => null,
        };

        return $holders === null ? DecisionReason::ADMINISTRATION_UNPROVABLE : self::growth($operation, $resource, $holders, $checks, $route, $change);
    }

    /**
     * Return the holders of the role the change is for, and of every role below
     * it, or null when its grantee is not a role.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @return \SineMacula\Laravel\Authorization\Administration\AffectedHolders|null
     */
    private static function holdersOfRole(OperationChange $change): ?AffectedHolders
    {
        return OperationGrantee::isRole($change->grantee) ? AffectedHolders::none()->ofRoles([$change->grantee->id]) : null;
    }

    /**
     * Return why a change reaching the holders is refused by the impact check,
     * or null when every holder is one the actor administers, across the
     * definition's reach.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\AffectedHolders  $holders
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function reaching(OperationResource $operation, ResourceReference $resource, AffectedHolders $holders, FurtherChecks $checks): ?DecisionReason
    {
        return Impact::refusal($operation, $resource, Impact::reachOf($operation->tenant), $holders->holders(), $checks);
    }

    /**
     * Return the role the change is for, read as stored, or null when its
     * grantee is not a role, or the role is gone.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @return \SineMacula\Laravel\Authorization\Models\Role|null
     */
    private static function roleOf(OperationChange $change): ?Role
    {
        $role = OperationGrantee::isRole($change->grantee) ? OperationGrantee::model($change->grantee) : null;

        return $role instanceof Role ? $role : null;
    }
}
