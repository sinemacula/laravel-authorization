<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Preview;

use SineMacula\Laravel\Authorization\Administration\AdministeredScope;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * The reach of a preview's admission (N84): the right to preview, decided as
 * the previewer on the preview resource, is weighed after the allow, inside the
 * one decision path (D22), by the administered-scope rule (see
 * `AdministeredScope`), so it can only refuse what the allow permitted.
 *
 * The stage applies to a check of `authorization:subject.preview` on a preview
 * resource (see `PreviewResource`); any other check passes it untouched. The
 * right's own decision is made in the preview's tenant (see `ResourceScope`),
 * so a previewer whose right reaches that tenant, from a parent with authority
 * over its subtree or from the platform, is admitted from its own context, and
 * one whose right does not reach it is refused before the stage. The stage then
 * decides the right again at the preview's node, the tenant alone, never below
 * it, or the platform, in the preview's application, so a preview for no
 * application needs the right for every application. A platform preview reaches
 * every tenant, so it is also refused when anything that denies or caps the
 * previewer anywhere could limit the right (see `PossessionLimits`): a
 * previewer allowed the right at the platform but denied it in one tenant may
 * preview in no platform scope. A preview it refuses is refused as
 * `administration.scope` at the `administration` stage, the trace naming it;
 * one it admits records one satisfied step there.
 *
 * No rank rule applies: an application restricts who may be previewed by
 * policy, on the preview resource's attributes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PreviewAdmission
{
    /**
     * Weigh the reach of the preview the check admits, when the decision
     * allowed the right to preview on a preview resource, deciding the further
     * checks it needs through the checks; return any other decision as it is.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    public static function weigh(Decision $decision, string $action, ?ResourceReference $resource, FurtherChecks $checks): Decision
    {
        $preview = $resource?->source;

        if (!$preview instanceof PreviewResource || $action !== PackagePermissions::SUBJECT_PREVIEW || !$decision->isAllowed()) {
            return $decision;
        }

        /** @var \SineMacula\Laravel\Authorization\Support\ResourceReference $resource */
        $reason = AdministeredScope::refusal($action, $resource, new GrantScope($preview->tenant, $preview->application, false), $checks);

        if ($reason === null) {
            return $decision->withStep(new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::SATISFIED));
        }

        $step = new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::REFUSED, cap: $reason->value);

        return Decision::deny($reason, DecisionStage::ADMINISTRATION, [], [...$decision->trace, $step])->withFreshness($decision->freshness);
    }
}
