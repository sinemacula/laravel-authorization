<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
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
 * descriptor (see `OperationResource::grantable()`); any other check passes it
 * untouched. Its constraints are weighed in order, the first that fails
 * refusing with its reason at the `administration` stage, the trace naming it.
 * A further check a constraint needs is decided as the actor, through every
 * stage up to the allow (see `FurtherChecks`):
 *
 * 1. an operation made while impersonating is refused as
 *    `administration.impersonating`, unless the subject is also allowed
 *    `authorization:administration.impersonated` on the same operation;
 * 2. for an operation on a subject, a principal or an identity (a grant, a
 *    revocation, an attachment, a detach, a boundary set or removal): -
 *    **owner** (D20): a change is made from the tenant that holds the grant row
 *    it changes, the platform's from the platform, or it is refused as
 *    `administration.owner` (see `OwnerConstraint`); a change that changes
 *    nothing edits nothing; - **scope**: a change that may widen authority is
 *    refused as `administration.scope` unless the actor is allowed its action
 *    across the whole reach: decided again in the grant's tenant, standing just
 *    below it for a grant that reaches the tenants below, so only authority
 *    that itself reaches below counts, and in the grant's application, so a
 *    grant to every application needs authority in every application. A
 *    platform-wide change is decided at platform scope by its own decision
 *    already (see `ResourceScope`); - **rank** (N76): unless the grantee is the
 *    actor, the actor must be strictly senior to the grantee, in the grant's
 *    scope, and to the rank a role grant would give it, or the change is
 *    refused as `administration.rank`, or `administration.rank_uncomparable`
 *    when either side's rank cannot be read (see `RankComparison`); a change
 *    that changes nothing included, so the refusal never depends on what the
 *    grantee holds; - **self**: a change to the actor itself, its principal or
 *    its identity, that may widen authority is refused as `administration.self`
 *    unless `authorization:administration.self` is also allowed on the
 *    operation; - a change that can only narrow (see `Narrowing`) is then
 *    allowed; - **possession** (N77): a direct grant of a permission must be
 *    provably held by the actor across its reach and lifetime, or explicitly
 *    grantable (see `Possession`), or it is refused as
 *    `administration.not_grantable` or `administration.unprovable`; - every
 *    other change that may widen authority, a role grant, a policy attachment,
 *    a boundary set or removal, a detach of a denying policy, is refused as
 *    `administration.unprovable`, the later parts of BL-65 not proving it yet;
 * 3. any other operation (a change to a definition, to a role's permissions or
 *    policies, or to a resource's policies) that may widen authority is refused
 *    as `administration.unprovable`; one that can only narrow, such as revoking
 *    a permission from a role or detaching an allow-only policy, is allowed on
 *    its action's decision.
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
        $operation = $resource?->source;
        $applies   = $operation instanceof OperationResource && $operation->action === $action && $action !== PackagePermissions::PERMISSION_GRANTABLE;

        if (!$resource instanceof ResourceReference || !$operation instanceof OperationResource || !$applies || !$decision->isAllowed()) {
            return $decision;
        }

        $reason = self::refusal($operation, $resource, $checks);

        if ($reason === null) {
            return $decision->withStep(new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::SATISFIED));
        }

        $step = new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::REFUSED, cap: $reason->value);

        return Decision::deny($reason, DecisionStage::ADMINISTRATION, [], [...$decision->trace, $step])->withFreshness($decision->freshness);
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
            return $operation->isNarrowing ? null : DecisionReason::ADMINISTRATION_UNPROVABLE;
        }

        return self::owner($operation, $checks)
            ?? self::scope($operation, $resource, $checks)
            ?? self::rank($operation, $checks)
            ?? self::self($operation, $resource, $checks)
            ?? self::widening($operation, $checks);
    }

    /**
     * Return `administration.owner` when the change edits a grant row held in
     * another tenant than the one the check is made from.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function owner(OperationResource $operation, FurtherChecks $checks): ?DecisionReason
    {
        return $operation->isUnchanged() || OwnerConstraint::isOwner($operation->tenant, $checks->origin) ? null : DecisionReason::ADMINISTRATION_OWNER;
    }

    /**
     * Return `administration.scope` when a change that may widen authority is
     * not allowed across its whole reach: its action decided again in the
     * grant's tenant, just below it for a grant that reaches below, in the
     * grant's application.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function scope(OperationResource $operation, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        $scope = $operation->change?->scope;

        if ($operation->isNarrowing || $scope === null) {
            return null;
        }

        $decide = static fn (): bool => $checks->decide($operation->action, $resource)->isAllowed();
        $below  = $operation->tenant !== null && $scope->includeSubtree;

        return TenantScope::within($operation->tenant, $scope->application, $decide, $below) ? null : DecisionReason::ADMINISTRATION_SCOPE;
    }

    /**
     * Return `administration.rank_uncomparable` or `administration.rank` when
     * the actor is not strictly senior to the grantee, in the grant's scope, as
     * the grant would leave it; a change to the actor itself is weighed by the
     * self rule instead.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function rank(OperationResource $operation, FurtherChecks $checks): ?DecisionReason
    {
        $change = $operation->change;

        if ($change === null || !RankComparison::isEnabled() || OperationGrantee::isSelf($operation, $checks->subject)) {
            return null;
        }

        $target  = OperationGrantee::model($change->grantee);
        $granted = $operation->action === PackagePermissions::ROLE_GRANT && $change->target instanceof Role ? $change->target->rank : null;

        if ($target !== null && RankComparison::canActOn($checks->subject, $target, self::scopeOf($operation), $granted)) {
            return null;
        }

        return $target !== null && RankComparison::isComparable($checks->subject) && RankComparison::isComparable($target)
            ? DecisionReason::ADMINISTRATION_RANK
            : DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE;
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
     * Return why a change that may widen authority is refused: a direct grant
     * of a permission as possession decides it, anything else as unprovable;
     * null for a change that can only narrow.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function widening(OperationResource $operation, FurtherChecks $checks): ?DecisionReason
    {
        $change     = $operation->change;
        $permission = $change?->target instanceof Permission ? $change->target->getAttribute('name') : null;

        if ($operation->isNarrowing) {
            return null;
        }

        return $change !== null && $operation->action === PackagePermissions::PERMISSION_GRANT && \is_string($permission)
            ? Possession::refusal($operation, $change, $permission, $checks)
            : DecisionReason::ADMINISTRATION_UNPROVABLE;
    }

    /**
     * Return the scope the operation's grant holds in, for its rank: its
     * tenant, or the platform, and its application.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @return \SineMacula\Laravel\Authorization\Support\AuthorizationScope
     */
    private static function scopeOf(OperationResource $operation): AuthorizationScope
    {
        $application = $operation->change?->scope->application;

        return $operation->tenant === null ? AuthorizationScope::platform($application) : AuthorizationScope::tenant($operation->tenant, $application);
    }
}
