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
 * administers, and so is a preview's admission, at the preview's node (see
 * `Preview\PreviewAdmission`), so what a preview discloses never exceeds what
 * its previewer may preview. A change or a preview it refuses is refused as
 * `administration.scope`.
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
     * whole reach of the action on the resource, an operation's or a preview's:
     * the action is not allowed in the reach, or anything that applies to the
     * actor anywhere in a reach wider than its node could limit the action;
     * null when it administers it all.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $reach
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    public static function refusal(string $action, ResourceReference $resource, GrantScope $reach, FurtherChecks $checks): ?DecisionReason
    {
        $below       = $reach->tenant !== null && $reach->includeSubtree;
        $administers = static fn (): bool => $checks->decide($action, $resource)->isAllowed() && !self::isLimited($action, $reach, $checks);

        return TenantScope::within($reach->tenant, $reach->application, $administers, $below) ? null : DecisionReason::ADMINISTRATION_SCOPE;
    }

    /**
     * Determine whether anything that applies to the actor anywhere in the
     * reach could limit the action, the reach in place: a reach of one tenant's
     * node alone is what its decision reads, so nothing more can; for a wider
     * one, the sources of the action, read in the scope in place, that cannot
     * be read limit it too.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $reach
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return bool
     */
    private static function isLimited(string $action, GrantScope $reach, FurtherChecks $checks): bool
    {
        if ($reach->tenant !== null && !$reach->includeSubtree) {
            return false;
        }

        $sources = $checks->sources($action);

        return $sources === null || PossessionLimits::isLimited($checks->subject, $action, $reach, $sources);
    }
}
