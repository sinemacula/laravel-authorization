<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;

/**
 * Decides a check on a tenant-owned resource in the right scope (AUTHZ-4.4,
 * AUTHZ-5.5, N9).
 *
 * A resource of the decision's tenant, or of a tenant below it, is decided in
 * the resource's own tenant, so grants there and those above it that reach the
 * tenants below count. A resource of any other tenant, every tenant-owned
 * resource when no tenant is active included, is denied as `tenant_scope`
 * before any policy is read, unless the subject holds the action's permission
 * through a platform-wide grant, when the decision runs at platform scope. The
 * application stays the request's. A resource with no tenant is decided where
 * the request is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ResourceScope
{
    /**
     * Decide the check on the resource through the callback, in the scope the
     * resource's tenant calls for, or deny it as out of scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \Closure(): \SineMacula\Laravel\Authorization\Evaluation\Decision  $decide
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    public static function decide(Subject $subject, string $action, ResourceReference $resource, \Closure $decide): Decision
    {
        $tenant = $resource->tenant;

        if ($tenant === null) {
            return $decide();
        }

        $application = TenantScope::currentApplication();
        $active      = TenantScope::currentChain()->tenant();
        $inScope     = $active !== null && TenantChain::isWithin($tenant, $active);

        if (!$inScope && !TenantScope::within(null, $application, static fn (): bool => SubjectGrants::holdsPermission($subject, $action))) {
            return Decision::deny(DecisionReason::TENANT_SCOPE, DecisionStage::TENANT);
        }

        return TenantScope::within($inScope ? $tenant : null, $application, $decide);
    }
}
