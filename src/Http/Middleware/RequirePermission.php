<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Http\Middleware;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authorization\Contracts\SupportsPermissions;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

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
class RequirePermission
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): mixed  $next
     * @param  string  ...$permissions
     * @return mixed
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException
     */
    public function handle(Request $request, \Closure $next, string ...$permissions): mixed
    {
        $user = $request->user();

        if ($user === null) {
            throw new AuthenticationException('Unauthenticated.');
        }

        if (!$user instanceof SupportsPermissions) {
            throw new AccessDeniedHttpException('This identity does not support permission checks.');
        }

        foreach (self::expand($permissions) as $permission) {
            if ($user->hasPermission($permission)) {
                return $next($request);
            }
        }

        throw new AccessDeniedHttpException('Permission required.');
    }

    /**
     * Flatten pipe-separated permission arguments so a single
     * middleware declaration like `permission:posts:edit|posts:delete`
     * behaves identically to the native Laravel
     * `permission:posts:edit,posts:delete` form.
     *
     * @param  array<int, string>  $arguments
     * @return array<int, string>
     */
    private static function expand(array $arguments): array
    {
        $permissions = [];

        foreach ($arguments as $argument) {
            foreach (\explode('|', $argument) as $candidate) {
                $candidate = \trim($candidate);

                if ($candidate !== '') {
                    $permissions[] = $candidate;
                }
            }
        }

        return $permissions;
    }
}
