<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Http\Middleware;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

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
class RequireRole
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): mixed  $next
     * @param  string  ...$roles
     * @return mixed
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException
     */
    public function handle(Request $request, \Closure $next, string ...$roles): mixed
    {
        $user = $request->user();

        if ($user === null) {
            throw new AuthenticationException('Unauthenticated.');
        }

        if (!$user instanceof SupportsRoles) {
            throw new AccessDeniedHttpException('This identity does not support role checks.');
        }

        foreach (self::expand($roles) as $role) {
            if ($user->hasRole($role)) {
                return $next($request);
            }
        }

        throw new AccessDeniedHttpException('Role required.');
    }

    /**
     * Flatten pipe-separated role arguments so a single
     * middleware declaration like `role:admin|editor` behaves
     * identically to the native Laravel `role:admin,editor`
     * form.
     *
     * @param  array<int, string>  $arguments
     * @return array<int, string>
     */
    private static function expand(array $arguments): array
    {
        $roles = [];

        foreach ($arguments as $argument) {
            foreach (\explode('|', $argument) as $candidate) {
                $candidate = \trim($candidate);

                if ($candidate !== '') {
                    $roles[] = $candidate;
                }
            }
        }

        return $roles;
    }
}
