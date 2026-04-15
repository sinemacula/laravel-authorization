<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Http\Middleware;

use SineMacula\Laravel\Authorization\Contracts\SupportsPermissions;

/**
 * Route middleware that admits only identities holding one of the
 * supplied permissions.
 *
 * Wired under the `permission` alias by the service provider.
 * Checks direct grants and role-inherited grants via the
 * identity's `hasPermission()` — policy-based decisions should
 * continue to use Laravel's `can:` middleware or the
 * `Authorization` facade, since route-middleware RBAC cannot
 * supply the resource and context a policy statement expects.
 * Arguments accept both Laravel-native comma separation
 * (`permission:posts:edit,posts:delete`) and Spatie-style pipe
 * separation (`permission:posts:edit|posts:delete`); both resolve
 * to OR semantics. For AND across several permissions, chain the
 * middleware — `->middleware(['permission:posts:edit', 'permission:posts:publish'])`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class RequirePermission extends AbstractAuthorizationMiddleware
{
    /**
     * @return class-string<\SineMacula\Laravel\Authorization\Contracts\SupportsPermissions>
     */
    protected function requiredContract(): string
    {
        return SupportsPermissions::class;
    }

    /**
     * @param  object  $principal
     * @param  string  $needle
     * @return bool
     */
    protected function matches(object $principal, string $needle): bool
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\SupportsPermissions $principal */
        return $principal->hasPermission($needle);
    }

    /**
     * @return string
     */
    protected function rejectionMessage(): string
    {
        return 'Permission required.';
    }
}
