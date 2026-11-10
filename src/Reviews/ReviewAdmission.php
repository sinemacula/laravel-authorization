<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews;

use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\AdministeredScope;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * The admission of an access review (N96): the reviewer is decided the review
 * right through ordinary `check()`, as itself, with its real session, denies,
 * boundaries, guardrails and caps, on the review's resource (see
 * `ReviewResource`), with the reviewed scope in place: the reviewed tenant, or
 * the platform for a review of the platform or of everywhere, and the
 * application named, or none otherwise, so a review of every application needs
 * authority held for every application. No rank rule applies: a review hands
 * out nothing, and a policy on the resource's attributes restricts who may
 * review what. An export is admitted to both review rights, decided together,
 * and every page, chunk and export is admitted again before it is read.
 *
 * A review of one tenant's node is decided at that tenant. A review across a
 * reach (rooted within a tenant, so the tenant and every tenant below it, or of
 * the platform, or of everywhere) is decided at the administration stage of the
 * same check by the administered-scope rule (see
 * `Administration\AdministeredScope`, the rule of #122) without mutation locks,
 * rank or self rules: the right is decided again just below the reach's tenant,
 * where only authority that reaches below counts, or at platform scope, and the
 * review is refused when anything that denies or caps the reviewer anywhere in
 * the reach could limit the right (see `Administration\PossessionLimits`), so
 * one child tenant's deny refuses a review of its parent's subtree. A review of
 * any application applying in one tenant is decided at that tenant with no
 * application, and is weighed across every application there in the same way,
 * so a deny, boundary or guardrail held for one application refuses it.
 *
 * A review run while someone impersonates the reviewer discloses what it reads
 * to the impersonator, so it is weighed as a delegated change made while
 * impersonating is (see `Administration\OperationConstraints`): the resource
 * names the impersonator (`resource.impersonated`, `impersonator_type` and
 * `impersonator_id`), and the review is refused as
 * `administration.impersonating` unless the reviewer is also allowed
 * `authorization:administration.impersonated` on the same review.
 *
 * A refusal is recorded and reported as `authorize()` records and reports any,
 * and throws `AuthorizationException` with the one generic `denied` line,
 * carrying the reviewer's own decision, a step-up the right needs included; it
 * discloses nothing of what the review would have read. A trusted review is
 * never admitted here: it is the explicit trusted entry point of
 * `AccessReview::trusted()`, never a fallback for a reviewer that cannot be
 * resolved, which an acting context refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReviewAdmission
{
    /** @var list<string> The review rights the administration stage weighs the reach of. */
    public const array ACTIONS = [PackagePermissions::REVIEW_READ, PackagePermissions::REVIEW_EXPORT];

    /**
     * Admit the review as the reviewer, deciding each right on the resource
     * with the reviewed scope in place, the read right when none is named, and
     * throw `AuthorizationException`, carrying the decision, at the first that
     * is not allowed. An export names both rights, decided together here, so it
     * is admitted only when the reviewer holds both.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $reviewer
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewResource  $resource
     * @param  string  ...$actions
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public static function admit(ActingContext $reviewer, ReviewResource $resource, string ...$actions): void
    {
        $manager  = self::manager($reviewer);
        $resource = $resource->actedBy($reviewer->impersonator);
        $actions  = $actions === [] ? [PackagePermissions::REVIEW_READ] : $actions;

        TenantScope::within($resource->scope->tenant, $resource->reach()->application, static function () use ($manager, $actions, $resource): void {
            foreach ($actions as $action) {
                self::authorize($manager, $action, $resource);
            }
        });
    }

    /**
     * Weigh the reach of a review the decision allowed: an allowed review right
     * on a review resource is refused at the administration stage, as
     * `administration.impersonating` when the reviewer is impersonated and
     * nothing allows that, else as `administration.scope` unless the reviewer's
     * right covers the review's whole reach; any other decision is returned as
     * it is.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    public static function weigh(Decision $decision, string $action, ?ResourceReference $resource, FurtherChecks $checks): Decision
    {
        $review = $resource?->source;

        if ($resource === null || !$review instanceof ReviewResource || !self::isWeighed($decision, $action)) {
            return $decision;
        }

        $reason = self::impersonation($review, $resource, $checks)
            ?? AdministeredScope::refusalOf($action, $resource, $review->reach(), $checks, $review->scope->isAcrossApplications());

        if ($reason === null) {
            return $decision->withStep(new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::SATISFIED));
        }

        $step = new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::REFUSED, cap: $reason->value);

        return Decision::deny($reason, DecisionStage::ADMINISTRATION, [], [...$decision->trace, $step])->withFreshness($decision->freshness);
    }

    /**
     * Return `administration.impersonating` when someone impersonates the
     * reviewer and the reviewer is not also allowed
     * `authorization:administration.impersonated` on the review; null
     * otherwise.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewResource  $review
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function impersonation(ReviewResource $review, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        $isRefused = $review->impersonator !== null && !$checks->decide(PackagePermissions::ADMINISTRATION_IMPERSONATED, $resource)->isAllowed();

        return $isRefused ? DecisionReason::ADMINISTRATION_IMPERSONATING : null;
    }

    /**
     * Determine whether the decision allowed one of the review rights.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @param  string  $action
     * @return bool
     */
    private static function isWeighed(Decision $decision, string $action): bool
    {
        return \in_array($action, self::ACTIONS, true) && $decision->isAllowed();
    }

    /**
     * Decide the reviewer the right on the resource in the scope in place,
     * recorded and reported as `authorize()` records and reports a refusal, and
     * throw `AuthorizationException` when it is not allowed: a step-up the
     * right needs is refused as any other denial, carrying the decision that
     * asked for it.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewResource  $resource
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private static function authorize(AuthorizationManager $manager, string $action, ReviewResource $resource): void
    {
        try {
            $manager->authorize($action, $resource);
        } catch (InsufficientAuthenticationException $exception) {
            throw self::refusal($exception->getDecision() ?? Decision::deny(DecisionReason::INSUFFICIENT_AUTHENTICATION, DecisionStage::SESSION));
        }
    }

    /**
     * Return the manager deciding about the reviewer, with the reviewer's caps,
     * in the scope in place, the review's reach, whatever tenant the reviewer
     * names (see `forActor()`), refusing when the package is not booted.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $reviewer
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private static function manager(ActingContext $reviewer): AuthorizationManager
    {
        $manager = AuthorizationManager::instance()?->forActor($reviewer->subject)
            ?? throw self::refusal(Decision::deny(DecisionReason::SUBJECT_UNRESOLVED, DecisionStage::SUBJECT));

        foreach ($reviewer->caps as $cap) {
            $manager = $manager->capped($cap);
        }

        return $manager;
    }

    /**
     * Return the refusal the decision makes, an `AuthorizationException` with
     * its reason and the one `denied` line, carrying the decision.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private static function refusal(Decision $decision): AuthorizationException
    {
        return ActingContext::refusal($decision);
    }
}
