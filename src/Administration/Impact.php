<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * The impact check of a change to a shared definition (AUTHZ-11.1, N78): a
 * change that widens what a role, a permission or a policy hands out is a new
 * distribution of authority to everyone who holds it, so every holder whose
 * authority grows must be one the actor administers, as a grant to it would be.
 *
 * The holders are read as a set (see `AffectedHolders`), and the change is then
 * weighed against all of them at once, at a fixed cost however many there are:
 *
 * - **bounded**: more holders than `authorization.administration.max_impact`
 *   allow, or some that cannot be read, refuse it as
 *   `administration.unprovable`, never approximated;
 * - **scope** (N79): the actor must administer the whole reach the holders'
 *   grants can have, the definition's owner and every tenant below it in every
 *   application, or the platform for a platform definition (see
 *   `AdministeredScope`): the operation's own action decided again there,
 *   standing just below the owner, so only authority that itself reaches below
 *   counts, and nothing that denies or caps the actor anywhere in the reach
 *   could limit it, or it is refused as `administration.scope`;
 * - **rank** (N76): the actor, ranked in the operation's tenant, must be
 *   strictly senior to the most senior rank any holder but itself holds
 *   anywhere in that reach (see `RankComparison::rankAcrossAll()`), and to a
 *   rank the change gives them, or it is refused as `administration.rank`, or
 *   `administration.rank_uncomparable` when a holder's or the actor's rank, or
 *   the reach, cannot be read;
 * - **self**: a change that reaches the actor itself, its principal or its
 *   identity, needs `authorization:administration.self` on the same operation,
 *   or it is refused as `administration.self`.
 *
 * A change that reaches no holder widens no one, and passes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Impact
{
    /**
     * Return why the change the operation makes to the holders is refused, or
     * null when every holder is one the actor administers; null holders stand
     * for a set over its limit.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $reach
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>|null  $holders
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @param  int|null  $granted
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    public static function refusal(
        OperationResource $operation,
        ResourceReference $resource,
        GrantScope $reach,
        ?array $holders,
        FurtherChecks $checks,
        ?int $granted = null,
    ): ?DecisionReason {
        if ($holders === null) {
            return DecisionReason::ADMINISTRATION_UNPROVABLE;
        }

        if ($holders === []) {
            return null;
        }

        return self::scope($operation, $resource, $reach, $checks)
            ?? self::rank($operation, $reach, $holders, $checks, $granted)
            ?? self::self($resource, $holders, $checks);
    }

    /**
     * Return the reach every grant of a definition the tenant owns can have:
     * the tenant and every tenant below it, or the platform for none, in every
     * application.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $owner
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     */
    public static function reachOf(?Reference $owner): GrantScope
    {
        return new GrantScope($owner, null, true);
    }

    /**
     * Return why a role of the rank, created or given a new rank, would rank
     * the actor's equal or senior, or null when it is junior to the actor in
     * the operation's tenant, unranked, or rank is no constraint.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  int|null  $rank
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    public static function juniorRank(OperationResource $operation, ?int $rank, FurtherChecks $checks): ?DecisionReason
    {
        if ($rank === null || !RankComparison::isEnabled()) {
            return null;
        }

        if (!RankComparison::isComparable($checks->subject)) {
            return DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE;
        }

        $actor = RankComparison::rankIn($checks->subject, $operation->tenant, null);

        return $actor !== null && $actor < $rank ? null : DecisionReason::ADMINISTRATION_RANK;
    }

    /**
     * Return `administration.scope` when the actor does not administer the
     * whole reach (see `AdministeredScope`).
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $reach
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function scope(OperationResource $operation, ResourceReference $resource, GrantScope $reach, FurtherChecks $checks): ?DecisionReason
    {
        return AdministeredScope::refusal($operation, $resource, $reach, $checks);
    }

    /**
     * Return `administration.rank_uncomparable` or `administration.rank` when
     * the actor is not strictly senior to every holder but itself anywhere in
     * the reach, and to the rank the change gives them.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $reach
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $holders
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @param  int|null  $granted
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function rank(OperationResource $operation, GrantScope $reach, array $holders, FurtherChecks $checks, ?int $granted): ?DecisionReason
    {
        $others = \array_filter($holders, static fn (Reference $holder): bool => !OperationGrantee::isActor($holder, $checks->subject));

        if (!RankComparison::isEnabled() || $others === []) {
            return null;
        }

        $ranks = self::ranks($operation, $reach, $others, $checks);

        return match (true) {
            $ranks === null                                                             => DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE,
            $ranks[0] !== null && $ranks[0] < \min($ranks[1], $granted ?? \PHP_INT_MAX) => null,
            default                                                                     => DecisionReason::ADMINISTRATION_RANK,
        };
    }

    /**
     * Return the actor's rank in the operation's tenant, null for none, and the
     * most senior rank any of the holders holds anywhere in the reach,
     * `PHP_INT_MAX` for none; or null when a side, or the reach, cannot be
     * read.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $reach
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Support\Reference>  $holders
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return array{int|null, int}|null
     */
    private static function ranks(OperationResource $operation, GrantScope $reach, array $holders, FurtherChecks $checks): ?array
    {
        $uncomparable = \array_filter($holders, static fn (Reference $holder): bool => !RankComparison::isComparableType($holder->type));
        $isComparable = RankComparison::isComparable($checks->subject) && $uncomparable === [];

        try {
            $held = $isComparable ? RankComparison::rankAcrossAll($holders, $reach) : null;
        } catch (\Throwable) {
            $isComparable = false;
            $held         = null;
        }

        return $isComparable ? [RankComparison::rankIn($checks->subject, $operation->tenant, $reach->application), $held ?? \PHP_INT_MAX] : null;
    }

    /**
     * Return `administration.self` when the holders include the actor itself
     * and the operation is not also allowed
     * `authorization:administration.self`.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $holders
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function self(ResourceReference $resource, array $holders, FurtherChecks $checks): ?DecisionReason
    {
        $reachesActor = \array_filter($holders, static fn (Reference $holder): bool => OperationGrantee::isActor($holder, $checks->subject)) !== [];

        return $reachesActor && !$checks->decide(PackagePermissions::ADMINISTRATION_SELF, $resource)->isAllowed() ? DecisionReason::ADMINISTRATION_SELF : null;
    }
}
