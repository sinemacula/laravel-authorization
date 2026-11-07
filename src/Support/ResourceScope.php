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
 * through a platform-wide grant, when the decision runs at platform scope; the
 * denies attached to the resource in its own tenant still apply there (see
 * `ResourcePolicyResolver`). That platform-wide grant only admits the resource:
 * the check is still decided by every stage, and the grant allows it at the
 * allow stage alone, after every deny and cap, the resource's tenant's
 * guardrails included (see `GuardrailResolver`). The application stays the
 * request's. A resource with no tenant is decided where the request is.
 *
 * A bulk check reads what its resources need in the scope each is decided in,
 * through `prepare()`, which groups them as `decide()` scopes them, admitting
 * none: a resource from outside the scope is read for at platform scope whether
 * or not its check is admitted.
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
        $inScope     = self::isInScope($tenant);

        if (!$inScope && !TenantScope::within(null, $application, static fn (): bool => SubjectGrants::holdsPermission($subject, $action))) {
            return Decision::deny(DecisionReason::TENANT_SCOPE, DecisionStage::TENANT);
        }

        return TenantScope::within($inScope ? $tenant : null, $application, $decide);
    }

    /**
     * Run the callback with each group of the resources, in the scope a check
     * on them is decided in: those with no tenant where the request is, those
     * of the decision's tenant or below it in their own tenant, and those of
     * any other tenant at platform scope, admitted or not. Nothing is decided.
     *
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Support\ResourceReference>  $resources
     * @param  \Closure(array<array-key, \SineMacula\Laravel\Authorization\Support\ResourceReference>): mixed  $prepare
     * @return void
     */
    public static function prepare(array $resources, \Closure $prepare): void
    {
        $here   = [];
        $scopes = [];

        foreach ($resources as $key => $resource) {
            $tenant = $resource->tenant;

            if ($tenant === null) {
                $here[$key] = $resource;

                continue;
            }

            $scope                      = self::isInScope($tenant) ? $tenant : null;
            $scopeKey                   = $scope === null ? '' : $scope->type . "\0" . $scope->id;
            $scopes[$scopeKey][0]       = $scope;
            $scopes[$scopeKey][1][$key] = $resource;
        }

        if ($here !== []) {
            $prepare($here);
        }

        $application = TenantScope::currentApplication();

        foreach ($scopes as [$scope, $group]) {
            TenantScope::within($scope, $application, static fn (): mixed => $prepare($group));
        }
    }

    /**
     * Determine whether the tenant is the decision's tenant or below it, so a
     * check on its resources is decided in it.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return bool
     */
    private static function isInScope(Reference $tenant): bool
    {
        $active = TenantScope::currentChain()->tenant();

        return $active !== null && TenantChain::isWithin($tenant, $active);
    }
}
