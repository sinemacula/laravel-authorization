<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Exceptions\GuardrailException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * Who may change the guardrails of a scope (AUTHZ-7.6): only an actor that
 * holds `authorization:guardrails:manage` from above it.
 *
 * The right is decided through `check()`, the one decision path (D22), so it is
 * held effectively: every deny, guardrail and boundary that applies to the
 * actor counts, and an inactive actor holds nothing. It is decided in the scope
 * above the one changed, so only a grant whose reach covers that scope from
 * above it counts:
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
 * like any other. An actor refused is refused with `GuardrailException`, its
 * reason `not_permitted`; with no authorization manager bound, every actor is
 * refused.
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
     * @param  \Illuminate\Database\Eloquent\Model  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GuardrailException
     */
    public static function assertPermitted(Model $actor, ?Reference $tenant): void
    {
        if (self::isPermitted($actor, $tenant)) {
            return;
        }

        throw GuardrailException::notPermitted(Reference::of($actor), $tenant);
    }

    /**
     * Determine whether the actor holds the right to manage guardrails from
     * above the tenant, or at platform scope for the platform.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return bool
     */
    private static function isPermitted(Model $actor, ?Reference $tenant): bool
    {
        $manager = AuthorizationManager::instance();

        if ($manager === null) {
            return false;
        }

        $parent = $tenant === null ? null : TenantChain::tree()->ancestors($tenant)[0] ?? null;
        $check  = static fn (): bool => $manager->for($actor)->check(PackagePermissions::GUARDRAILS_MANAGE)->isAllowed();

        return TenantScope::within($parent, TenantScope::currentApplication(), $check, $parent !== null);
    }
}
