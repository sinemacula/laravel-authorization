<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Http\Middleware;

use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;

/**
 * Route middleware that admits only identities holding one of the
 * supplied roles.
 *
 * Wired under the `role` alias by the service provider.
 * Arguments accept both Laravel-native comma separation
 * (`role:admin,editor`) and Spatie-style pipe separation
 * (`role:admin|editor`); both resolve to OR semantics. For AND
 * across several roles, chain the middleware —
 * `->middleware(['role:admin', 'role:oncall'])`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class RequireRole extends AbstractAuthorizationMiddleware
{
    /**
     * @return class-string<\SineMacula\Laravel\Authorization\Contracts\SupportsRoles>
     */
    protected function requiredContract(): string
    {
        return SupportsRoles::class;
    }

    /**
     * @param  object  $principal
     * @param  string  $needle
     * @return bool
     */
    protected function matches(object $principal, string $needle): bool
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\SupportsRoles $principal */
        return $principal->hasRole($needle);
    }

    /**
     * @return string
     */
    protected function rejectionMessage(): string
    {
        return 'Role required.';
    }
}
