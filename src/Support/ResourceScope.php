<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Preview\PreviewResource;
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
 * request's. A resource with no tenant is decided where the request is, but an
 * operation or a preview resource with none at platform scope. A preview
 * resource of a decision made just below its tenant (see `PreviewResource`) is
 * decided just below that tenant, when it is in scope.
 *
 * A bulk check reads what its resources need in the scope each is decided in,
 * through `prepare()`, which groups them as `decide()` scopes them, admitting
 * none: a resource from outside the scope is read for at platform scope whether
 * or not its check is admitted. A resource whose place in the tree cannot be
 * read is left out, so its own check fails when it is reached. `scopeOf()`
 * names the scope a resource is decided in, so what is read for one resource is
 * read with the others decided in the same scope alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ResourceScope
{
    /** @var string The key of the scope a resource with no tenant is decided in: where the request is. */
    public const string HERE = 'here';

    /** @var string The key of the scope a resource of a tenant outside the decision's is decided in. */
    public const string PLATFORM = 'platform';

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
            return self::isPlatformWide($resource) ? TenantScope::within(null, TenantScope::currentApplication(), $decide) : $decide();
        }

        $application = TenantScope::currentApplication();
        $inScope     = self::isInScope($tenant);

        if (!$inScope && !TenantScope::within(null, $application, static fn (): bool => SubjectGrants::holdsPermission($subject, $action))) {
            return Decision::deny(DecisionReason::TENANT_SCOPE, DecisionStage::TENANT);
        }

        return TenantScope::within($inScope ? $tenant : null, $application, $decide, $inScope && self::isBelow($resource));
    }

    /**
     * Run the callback with each group of the resources, in the scope a check
     * on them is decided in: those with no tenant where the request is, but an
     * operation or preview resource with none at platform scope, those of the
     * decision's tenant or below it in their own tenant, and those of any other
     * tenant at platform scope, admitted or not. Nothing is decided, and
     * nothing thrown: what is read ahead only supplies data, so a resource
     * whose place in the tree cannot be read is left out, and a group whose
     * callback throws is left to its checks, each of which reads its own, and
     * fails alone, when it is reached.
     *
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Support\ResourceReference>  $resources
     * @param  \Closure(array<array-key, \SineMacula\Laravel\Authorization\Support\ResourceReference>): mixed  $prepare
     * @return void
     */
    public static function prepare(array $resources, \Closure $prepare): void
    {
        $application = TenantScope::currentApplication();

        foreach (self::groups($resources) as $scope => [$tenant, $group]) {
            try {
                $scope === self::HERE ? $prepare($group) : TenantScope::within($tenant, $application, static fn (): mixed => $prepare($group));
            } catch (\Throwable) {
                continue;
            }
        }
    }

    /**
     * Return the key of the scope a check on the resource is decided in, for a
     * decision whose tenant is the one given: `HERE` for a resource with no
     * tenant, `PLATFORM` for an operation or preview resource with none, the
     * resource's tenant for one of that tenant or below it, and `PLATFORM` for
     * one of any other tenant, every tenant-owned resource when no tenant is
     * given included. Two resources with the same key are decided in the same
     * scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $active
     * @return string
     */
    public static function scopeOf(ResourceReference $resource, ?Reference $active): string
    {
        $tenant = $resource->tenant;

        if ($tenant === null) {
            return self::isPlatformWide($resource) ? self::PLATFORM : self::HERE;
        }

        return self::isWithinActive($tenant, $active) ? 'tenant:' . \strlen($tenant->type) . ':' . $tenant->type . ':' . $tenant->id : self::PLATFORM;
    }

    /**
     * Return the resources grouped by the scope a check on them is decided in,
     * each group with the tenant it is decided in: none where the request is,
     * since those resources have none, and none at platform scope; a resource
     * whose place in the tree cannot be read is left out.
     *
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Support\ResourceReference>  $resources
     * @return array<string, array{\SineMacula\Laravel\Authorization\Support\Reference|null, array<array-key, \SineMacula\Laravel\Authorization\Support\ResourceReference>}>
     */
    private static function groups(array $resources): array
    {
        $groups = [];

        foreach ($resources as $key => $resource) {
            try {
                $scope = self::scopeOf($resource, $resource->tenant === null ? null : TenantScope::currentChain()->tenant());
            } catch (\Throwable) {
                continue;
            }

            $groups[$scope][0]       = $scope === self::PLATFORM ? null : $resource->tenant;
            $groups[$scope][1][$key] = $resource;
        }

        return $groups;
    }

    /**
     * Determine whether a resource with no tenant is decided at platform scope
     * rather than where the request is: an operation resource, whose change
     * holds platform-wide, or a preview resource, whose preview is made at the
     * platform.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @return bool
     */
    private static function isPlatformWide(ResourceReference $resource): bool
    {
        return $resource->source instanceof OperationResource || $resource->source instanceof PreviewResource;
    }

    /**
     * Determine whether a resource in scope is decided just below its tenant
     * rather than in it: a preview resource of a decision made there.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @return bool
     */
    private static function isBelow(ResourceReference $resource): bool
    {
        return $resource->source instanceof PreviewResource && $resource->source->isBelow;
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
        return self::isWithinActive($tenant, TenantScope::currentChain()->tenant());
    }

    /**
     * Determine whether the tenant is the given decision's tenant or below it.
     * No tenant is within no decision's tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $active
     * @return bool
     */
    private static function isWithinActive(Reference $tenant, ?Reference $active): bool
    {
        return $active !== null && TenantChain::isWithin($tenant, $active);
    }
}
