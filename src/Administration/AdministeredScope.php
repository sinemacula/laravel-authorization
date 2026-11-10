<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * The administered-scope rule (N79): a change that may widen authority is made
 * only by an actor that administers the whole of its reach, so its action is
 * allowed everywhere the change reaches, never just at the node it is decided
 * at.
 *
 * The change's own action is decided again in the reach's tenant, standing just
 * below it for a reach that includes the tenants below, so only authority that
 * itself reaches below counts, or at platform scope for a platform-wide reach,
 * and in the reach's application, so a reach of every application needs
 * authority in every application. A decision at one node reads only what
 * applies there, so a reach wider than its node, a platform-wide one or one
 * that includes the tenants below, is also refused when anything that denies or
 * caps the actor anywhere in it could limit the action (see
 * `PossessionLimits`): a deny whose actions overlap it, conditional or not, a
 * boundary or a guardrail that does not allow it whole, a session cap that does
 * not cover it, or a tree, row or document that cannot be read. So an actor
 * allowed the action at the platform but denied it in one tenant administers no
 * platform-wide reach, and a parent's administrator denied it in one child
 * administers no subtree that holds the child.
 *
 * Every change to a subject (see `OperationConstraints`) and every impact check
 * of a definition or a resource-policy attachment (see `Impact`) is weighed by
 * this one rule, so what a change reaches never exceeds what its actor
 * administers. A change it refuses is refused as `administration.scope`.
 *
 * A further right such a change needs beside its action, the self, unbounded,
 * impersonated or grantable right, is weighed across the same reach by the same
 * rule (see `isAllowedAcross()`, and `isLimited()` for a right decided in the
 * reach already), so an actor allowed the right at the platform but denied it
 * in one tenant cannot use it on a change that reaches that tenant; each caller
 * refuses with the right's own reason.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AdministeredScope
{
    /**
     * Return `administration.scope` when the actor does not administer the
     * whole reach of the operation: its action is not allowed in the reach, or
     * anything that applies to the actor anywhere in a reach wider than its
     * node could limit the action; null when it administers it all.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $reach
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    public static function refusal(OperationResource $operation, ResourceReference $resource, GrantScope $reach, FurtherChecks $checks): ?DecisionReason
    {
        return self::refusalOf($operation->action, $resource, $reach, $checks);
    }

    /**
     * Return `administration.scope` when the actor's authority for the action
     * does not cover the whole reach, decided as `refusal()` decides an
     * operation's: the action is not allowed on the resource in the reach, or
     * anything that applies to the actor anywhere in a reach wider than its
     * node could limit it; null when it covers it all. An access review is
     * admitted across its reach by this rule (see `Reviews\ReviewAdmission`),
     * with no lock, rank or self rule.
     *
     * A reach across applications, every application at once rather than the
     * grants held for every application, is wider than its node in the
     * application dimension as a subtree is in the tenant one: a decision with
     * no application reads only what is held for every application, so anything
     * held for one application that could limit the action limits it too.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $reach
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @param  bool  $isAcrossApplications
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    public static function refusalOf(string $action, ResourceReference $resource, GrantScope $reach, FurtherChecks $checks, bool $isAcrossApplications = false): ?DecisionReason
    {
        $below       = $reach->tenant !== null && $reach->includeSubtree;
        $administers = static fn (): bool => $checks->decide($action, $resource)->isAllowed() && !self::isLimited($action, $reach, $checks, $isAcrossApplications);

        return TenantScope::within($reach->tenant, $reach->application, $administers, $below) ? null : DecisionReason::ADMINISTRATION_SCOPE;
    }

    /**
     * Determine whether a further right the operation needs beside its action
     * is allowed on it everywhere the change reaches: at the node the operation
     * is decided at, as its action is, and across the whole reach by the rule
     * `refusalOf()` applies to the action, so anything that denies or caps the
     * right anywhere in a reach wider than its node refuses it.
     *
     * @param  string  $right
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $reach
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @param  bool  $isAcrossApplications
     * @return bool
     */
    public static function isAllowedAcross(string $right, ResourceReference $resource, GrantScope $reach, FurtherChecks $checks, bool $isAcrossApplications = false): bool
    {
        return $checks->decide($right, $resource)->isAllowed() && self::refusalOf($right, $resource, $reach, $checks, $isAcrossApplications) === null;
    }

    /**
     * Determine whether anything that applies to the actor anywhere in the
     * reach could limit the action, the reach in place: a reach of one tenant's
     * node alone, in one application or in none, is what its decision reads, so
     * nothing more can; for a wider one, below the tenant, at the platform or
     * across applications, the sources of the action, read in the scope in
     * place, that cannot be read limit it too. A right already decided in the
     * reach (see `Possession`) is weighed by this alone. What is read is
     * remembered for the rest of the decision, for the action, the reach and
     * the scope in place (see `FurtherChecks::limited()`), so a change that
     * weighs the same right for each policy it hands out reads it once.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $reach
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @param  bool  $isAcrossApplications
     * @return bool
     */
    public static function isLimited(string $action, GrantScope $reach, FurtherChecks $checks, bool $isAcrossApplications = false): bool
    {
        if ($reach->tenant !== null && !$reach->includeSubtree && !$isAcrossApplications) {
            return false;
        }

        $limit = static function () use ($action, $reach, $checks): bool {
            $sources = $checks->sources($action);

            return $sources === null || PossessionLimits::isLimited($checks->subject, $action, $reach, $sources);
        };

        return $checks->limited(self::keyOf($action, $reach, $isAcrossApplications), $limit);
    }

    /**
     * Return the key what limits the action across the reach is remembered
     * under: the action, the reach, whether it spans every application, and the
     * scope in place, which the action's sources are read in.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $reach
     * @param  bool  $isAcrossApplications
     * @return string
     */
    private static function keyOf(string $action, GrantScope $reach, bool $isAcrossApplications): string
    {
        $tenant = TenantScope::currentTenant();
        $parts  = [
            $action,
            $reach->tenant?->type,
            $reach->tenant?->id,
            $reach->application,
            $reach->includeSubtree,
            $isAcrossApplications,
            $tenant[0] ?? null,
            $tenant[1] ?? null,
            TenantScope::currentApplication(),
            TenantScope::isBelowTenant(),
        ];

        return \serialize($parts);
    }
}
