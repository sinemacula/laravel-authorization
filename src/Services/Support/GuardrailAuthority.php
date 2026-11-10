<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\GuardrailException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * Who may change the guardrails of a scope (AUTHZ-7.6): only an acting subject
 * that holds `authorization:guardrail.manage` from above it.
 *
 * The right is decided through `check()`, the one decision path (D22), as the
 * acting context's subject, with its session and caps, so it is held
 * effectively: every deny, boundary and session cap that applies to the actor
 * counts, and an inactive actor holds nothing. The guardrails never count: a
 * check of exactly `authorization:guardrail.manage` is exempt from the
 * guardrail stage, so no guardrail, one that does not allow the permission or
 * cannot be read included, ever keeps an actor from changing the guardrails,
 * its own removal included. It is decided in the scope above the one changed,
 * so only a grant whose reach covers that scope from above it counts:
 *
 * - for a tenant's guardrail, just below the tenant's parent in the tenant
 *   tree, so a grant held at an ancestor counts only when it reaches the
 *   tenants below it, a platform-wide grant counts, and one held within the
 *   tenant itself never does; a tenant with no parent is changed from the
 *   platform;
 * - for a platform guardrail, at platform scope, where only a platform-wide
 *   grant counts.
 *
 * The decision keeps the request's application, and is recorded and reported
 * like any other. The guardrail service asks inside the change's transaction,
 * before anything is read or written. An actor refused is refused with
 * `GuardrailException`, its reason `not_permitted`; with no authorization
 * manager bound, every actor is refused. An actor someone is impersonating is
 * refused as `administration.impersonating`, with `AuthorizationException`,
 * unless `authorization:administration.impersonated` is also allowed it in the
 * same scope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GuardrailAuthority
{
    /**
     * Refuse the actor unless it may change the guardrails of the tenant, or of
     * the platform when the tenant is null.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GuardrailException
     */
    public static function assertPermitted(ActingContext $actor, ?Reference $tenant): void
    {
        if (AuthorizationManager::instance() === null || !self::decide($actor, $tenant, PackagePermissions::GUARDRAIL_MANAGE)->isAllowed()) {
            throw GuardrailException::notPermitted($actor->principal(), $tenant);
        }

        $impersonated = $actor->isImpersonating() ? self::decide($actor, $tenant, PackagePermissions::ADMINISTRATION_IMPERSONATED) : null;

        if ($impersonated !== null && !$impersonated->isAllowed()) {
            throw self::impersonating($impersonated);
        }
    }

    /**
     * Return the refusal of a change made while impersonating, carrying the
     * decision that did not allow it, with the refusal's step added.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $impersonated
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private static function impersonating(Decision $impersonated): AuthorizationException
    {
        $step = new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::REFUSED, cap: DecisionReason::ADMINISTRATION_IMPERSONATING->value);

        return ActingContext::refusal(Decision::deny(DecisionReason::ADMINISTRATION_IMPERSONATING, DecisionStage::ADMINISTRATION, [], [...$impersonated->trace, $step]));
    }

    /**
     * Decide the action as the actor from above the tenant, or at platform
     * scope for the platform.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private static function decide(ActingContext $actor, ?Reference $tenant, string $action): Decision
    {
        $parent = $tenant === null ? null : TenantChain::tree()->ancestors($tenant)[0] ?? null;

        return TenantScope::within($parent, TenantScope::currentApplication(), static fn (): Decision => $actor->decide($action), $parent !== null);
    }
}
