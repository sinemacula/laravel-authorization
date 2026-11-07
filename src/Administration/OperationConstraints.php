<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * The administration stage of a decision (AUTHZ-11.1): the constraints of the
 * administration operation a check is about, weighed after the allow, inside
 * the one decision path (D22), so they can only refuse what the allow
 * permitted, and a screen asking the same check gets the same refusal.
 *
 * The stage applies to a check of an administration action on an operation
 * resource of that action (see `OperationResource`), but never to a grantable
 * descriptor (see `OperationResource::isDescriptor()`); any other check passes
 * it untouched. The action's own decision is made in the tenant of the row the
 * change edits (see `ResourceScope`), so an actor whose authority for the
 * action reaches that tenant, from a parent with authority over its subtree or
 * from the platform, changes the row from its own context, and one whose
 * authority does not reach it is refused before the stage. The stage's
 * constraints are then weighed in order, the first that fails refusing with its
 * reason at the `administration` stage, the trace naming it. A further check a
 * constraint needs is decided as the actor, through every stage up to the allow
 * (see `FurtherChecks`):
 *
 * 1. an operation made while impersonating is refused as
 *    `administration.impersonating`, unless the subject is also allowed
 *    `authorization:administration.impersonated` on the same operation;
 * 2. an operation on a subject, a principal or an identity (a grant, a
 *    revocation, an attachment, a detach, a boundary set or removal), is
 *    weighed by the constraints of a change to a subject, listed below;
 * 3. any other operation, a change to a definition, to a role's permissions,
 *    policies or parent, or to a resource's policies, is weighed by the owner
 *    rule and by what it changes (see `DefinitionConstraints`).
 *
 * The constraints of a change to a subject, in order:
 *
 * - **scope**: a change that may widen authority is refused as
 *   `administration.scope` unless the actor is allowed its action across the
 *   whole reach: decided again in the grant's tenant, standing just below it
 *   for a grant that reaches the tenants below, so only authority that itself
 *   reaches below counts, and in the grant's application, so a grant to every
 *   application needs authority in every application; a platform-wide change is
 *   decided at platform scope by its own decision already;
 * - **rank** (N76): unless the grantee is the actor, the actor, ranked in the
 *   grant's own tenant and application, must be strictly senior to the most
 *   senior rank the grantee holds anywhere the change reaches, and to the rank
 *   a role grant would give it, or the change is refused as
 *   `administration.rank`, or `administration.rank_uncomparable` when either
 *   side's rank, or the reach, cannot be read (see `RankComparison`); a change
 *   that changes nothing included, so the refusal never depends on what the
 *   grantee holds;
 * - **self**: a change to the actor itself, its principal or its identity, that
 *   may widen authority is refused as `administration.self` unless
 *   `authorization:administration.self` is also allowed on the operation;
 * - a change that can only narrow (see `Narrowing`) is then allowed;
 * - **possession** (N77): a direct grant of a permission must be provably held
 *   by the actor across its reach and lifetime, or explicitly grantable there
 *   (see `Possession`), or it is refused as `administration.not_grantable` or
 *   `administration.unprovable`;
 * - **roles**: a role grant hands out the role's whole authority, every
 *   permission and policy it and its ancestors carry (see `RoleAuthority`),
 *   each by its own route; a chain that cannot be read is unprovable;
 * - **policies**: a policy attachment needs the policy route, containment or
 *   `authorization:policy.grantable` on the policy's digest (see
 *   `PolicyRoute`);
 * - **boundaries**: a boundary that only adds or tightens a cap narrows (see
 *   `Narrowing`); one that replaces a boundary with a wider one, or a removal,
 *   cannot be bounded in general, so it is refused as
 *   `administration.unprovable` unless the actor is also allowed
 *   `authorization:administration.unbounded` on the same operation;
 * - every other change that may widen authority, a detach of a denying policy
 *   included, is refused as `administration.unprovable`.
 *
 * The owner rule (D20, see `OwnerConstraint`) governs definitions, their
 * membership and their attachments, never grant rows: who may change a grant
 * row is the administered scope alone.
 *
 * An allow that passes records one satisfied step at the stage.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class OperationConstraints
{
    /**
     * Weigh the constraints of the operation the check is about, when the
     * decision allowed an administration action on an operation resource of
     * that action, deciding any further check they need through the checks;
     * return any other decision as it is.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    public static function weigh(Decision $decision, string $action, ?ResourceReference $resource, FurtherChecks $checks): Decision
    {
        if (!self::isWeighed($decision, $action, $resource)) {
            return $decision;
        }

        $reason = self::refusal($resource->source, $resource, $checks);

        if ($reason === null) {
            return $decision->withStep(new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::SATISFIED));
        }

        $step = new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::REFUSED, cap: $reason->value);

        return Decision::deny($reason, DecisionStage::ADMINISTRATION, [], [...$decision->trace, $step])->withFreshness($decision->freshness);
    }

    /**
     * Determine whether the stage weighs the decision: it allowed an
     * administration action on an operation resource of that action, other than
     * a grantable descriptor.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @return bool
     *
     * @phpstan-assert-if-true !null $resource
     * @phpstan-assert-if-true \SineMacula\Laravel\Authorization\Administration\OperationResource $resource->source
     */
    private static function isWeighed(Decision $decision, string $action, ?ResourceReference $resource): bool
    {
        $operation = $resource?->source;
        $applies   = $operation instanceof OperationResource && $operation->action === $action && !$operation->isDescriptor();

        return $applies && $decision->isAllowed();
    }

    /**
     * Return the reason the first constraint that fails refuses the operation,
     * or null when every one holds.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function refusal(OperationResource $operation, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        if ($operation->impersonator !== null && !$checks->decide(PackagePermissions::ADMINISTRATION_IMPERSONATED, $resource)->isAllowed()) {
            return DecisionReason::ADMINISTRATION_IMPERSONATING;
        }

        if (!OperationGrantee::isSubject($operation)) {
            return DefinitionConstraints::refusal($operation, $resource, $checks);
        }

        $change = $operation->change;

        return self::scope($operation, $change, $resource, $checks)
            ?? self::rank($operation, $change, $checks)
            ?? self::self($operation, $resource, $checks)
            ?? self::widening($operation, $change, $resource, $checks);
    }

    /**
     * Return `administration.scope` when a change that may widen authority is
     * not allowed across its whole reach: its action decided again in the
     * grant's tenant, just below it for a grant that reaches below, in the
     * grant's application.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function scope(OperationResource $operation, OperationChange $change, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        if ($operation->isNarrowing) {
            return null;
        }

        $decide = static fn (): bool => $checks->decide($operation->action, $resource)->isAllowed();
        $below  = $operation->tenant !== null && $change->scope->includeSubtree;

        return TenantScope::within($operation->tenant, $change->scope->application, $decide, $below) ? null : DecisionReason::ADMINISTRATION_SCOPE;
    }

    /**
     * Return `administration.rank_uncomparable` or `administration.rank` when
     * the actor is not strictly senior to the grantee, as the grant would leave
     * it, anywhere the change reaches; a change to the actor itself is weighed
     * by the self rule instead.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function rank(OperationResource $operation, OperationChange $change, FurtherChecks $checks): ?DecisionReason
    {
        if (!RankComparison::isEnabled() || OperationGrantee::isSelf($operation, $checks->subject)) {
            return null;
        }

        $ranks = self::ranks($operation, $change, $checks->subject);

        return match (true) {
            $ranks === null                             => DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE,
            $ranks[0] !== null && $ranks[0] < $ranks[1] => null,
            default                                     => DecisionReason::ADMINISTRATION_RANK,
        };
    }

    /**
     * Return the actor's rank, null for none, in the grant's own tenant and
     * application, and the most senior rank the grantee would hold anywhere the
     * change reaches, `PHP_INT_MAX` for none; or null when either side's rank,
     * or the reach, cannot be read.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  \SineMacula\Laravel\Authorization\Subject  $actor
     * @return array{int|null, int}|null
     */
    private static function ranks(OperationResource $operation, OperationChange $change, Subject $actor): ?array
    {
        $target = OperationGrantee::model($change->grantee);

        if ($target === null || !RankComparison::isComparable($actor) || !RankComparison::isComparable($target)) {
            return null;
        }

        try {
            $held = RankComparison::rankAcross($target, $change->scope);
        } catch (\Throwable) {
            return null;
        }

        $granted = $operation->action === PackagePermissions::ROLE_GRANT && $change->target instanceof Role ? $change->target->rank : null;

        return [RankComparison::rankIn($actor, $operation->tenant, $change->scope->application), \min($held ?? \PHP_INT_MAX, $granted ?? \PHP_INT_MAX)];
    }

    /**
     * Return `administration.self` when a change to the actor itself that may
     * widen authority is not also allowed `authorization:administration.self`.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function self(OperationResource $operation, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        $isRefused = !$operation->isNarrowing
            && OperationGrantee::isSelf($operation, $checks->subject)
            && !$checks->decide(PackagePermissions::ADMINISTRATION_SELF, $resource)->isAllowed();

        return $isRefused ? DecisionReason::ADMINISTRATION_SELF : null;
    }

    /**
     * Return why a change that may widen authority is refused, by what it hands
     * out: a permission by the permission route (see `Possession`), a role by
     * the routes of its whole authority (see `RoleAuthority`), a policy by the
     * policy route (see `PolicyRoute`), a boundary replaced by a wider one or
     * removed by the further right `authorization:administration.unbounded`,
     * and anything else, a detach of a denying policy included, as unprovable;
     * null for a change that can only narrow.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function widening(OperationResource $operation, OperationChange $change, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        if ($operation->isNarrowing) {
            return null;
        }

        $target     = $change->target;
        $action     = $operation->action;
        $isBoundary = \in_array($action, [PackagePermissions::BOUNDARY_SET, PackagePermissions::BOUNDARY_REMOVE], true);

        return match (true) {
            $action === PackagePermissions::PERMISSION_GRANT && $target instanceof Permission => Possession::refusal($operation, $change, $target, $checks),
            $action === PackagePermissions::ROLE_GRANT       && $target instanceof Role       => self::roleGranted($operation, $change, $target, $checks),
            $action === PackagePermissions::POLICY_ATTACH    && $target instanceof Policy     => PolicyRoute::refusal($operation, $change, $target, $checks),
            $isBoundary                                                                       => self::unbounded($resource, $checks),
            default                                                                           => DecisionReason::ADMINISTRATION_UNPROVABLE,
        };
    }

    /**
     * Return `administration.unprovable` unless the operation, a boundary
     * replaced by a wider one or removed, is also allowed
     * `authorization:administration.unbounded`.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function unbounded(ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        return $checks->decide(PackagePermissions::ADMINISTRATION_UNBOUNDED, $resource)->isAllowed() ? null : DecisionReason::ADMINISTRATION_UNPROVABLE;
    }

    /**
     * Return why granting the role is refused by the routes of its whole
     * authority, its ancestors' included, across the grant's reach and
     * lifetime, or null when every one passes; a chain that cannot be read
     * whole is unprovable.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function roleGranted(OperationResource $operation, OperationChange $change, Role $role, FurtherChecks $checks): ?DecisionReason
    {
        $authority = RoleAuthority::of([$role->id]);

        return $authority === null ? DecisionReason::ADMINISTRATION_UNPROVABLE : $authority->refusal($operation, $change, $checks);
    }
}
