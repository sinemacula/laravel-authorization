<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * The administration stage of a decision (AUTHZ-11.1): the constraints of the
 * administration operation a check is about, weighed after the allow, inside
 * the one decision path (D22), so they can only refuse what the allow
 * permitted, and a screen asking the same check gets the same refusal.
 *
 * The stage applies to a check of an administration action on an operation
 * resource of that action (see `OperationResource`); any other check passes it
 * untouched. Its constraints are weighed in order, the first that fails
 * refusing with its reason at the `administration` stage, the trace naming it:
 *
 * 1. an operation made while impersonating is refused as
 *    `administration.impersonating`, unless the subject is also allowed
 *    `authorization:administration.impersonated` on the same operation, decided
 *    as any check is;
 * 2. an operation that may widen what anyone may do is refused as
 *    `administration.unprovable`: the scope, owner, rank, self, grantable,
 *    expiry and impact rules that would prove it permitted are not evaluated
 *    yet, so delegated administration grants nothing it cannot justify. An
 *    operation that can only narrow, such as revoking a permission or detaching
 *    an allow-only policy, is allowed on its action's decision.
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
     * that action, deciding any further check they need through the callback;
     * return any other decision as it is.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @param  \Closure(string): \SineMacula\Laravel\Authorization\Evaluation\Decision  $decide
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    public static function weigh(Decision $decision, string $action, ?ResourceReference $resource, \Closure $decide): Decision
    {
        $operation = $resource?->source;

        if (!$decision->isAllowed() || !$operation instanceof OperationResource || $operation->action !== $action) {
            return $decision;
        }

        $reason = self::refusal($operation, $decide);

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
     * @param  \Closure(string): \SineMacula\Laravel\Authorization\Evaluation\Decision  $decide
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function refusal(OperationResource $operation, \Closure $decide): ?DecisionReason
    {
        if ($operation->impersonator !== null && !$decide(PackagePermissions::ADMINISTRATION_IMPERSONATED)->isAllowed()) {
            return DecisionReason::ADMINISTRATION_IMPERSONATING;
        }

        return $operation->isNarrowing ? null : DecisionReason::ADMINISTRATION_UNPROVABLE;
    }
}
