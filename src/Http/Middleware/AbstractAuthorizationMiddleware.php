<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Http\Middleware;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationMiddlewareMisconfiguredException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Shared template method for the shipped authorization middleware.
 *
 * Concrete middleware (`RequireRole`, `RequirePermission`) plug
 * three hooks into a single `handle()` body: the capability
 * contract the identity must implement, the per-needle check, and
 * the message rendered on a legitimate deny. Every other step —
 * resolving the current principal, guarding against the anonymous
 * case, flattening pipe-and-comma arguments, distinguishing the
 * misconfiguration failure from an authorization deny — lives
 * here, so the two classes stay three-method leaves and future
 * changes to the handle path land in exactly one file (see
 * issues #81, #82, #83, #85).
 *
 * Principal resolution delegates to the
 * `Authorization::currentPrincipal()` facade so the middleware
 * resolves the same principal as the facade, Gate, and Blade
 * directives — consumers wiring a custom `PrincipalResolver` see
 * it honoured at every surface.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract class AbstractAuthorizationMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): mixed  $next
     * @param  string  ...$needles
     * @return mixed
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationMiddlewareMisconfiguredException
     */
    public function handle(Request $request, \Closure $next, string ...$needles): mixed
    {
        $principal = Authorization::currentPrincipal();

        if ($principal === null) {
            throw new AuthenticationException('Unauthenticated.');
        }

        $contract = $this->requiredContract();

        if (!$principal instanceof $contract) {
            throw new AuthorizationMiddlewareMisconfiguredException($contract, static::class);
        }

        foreach (self::expand($needles) as $needle) {
            if ($this->matches($principal, $needle)) {
                return $next($request);
            }
        }

        throw new AccessDeniedHttpException($this->rejectionMessage());
    }

    /**
     * Return the fully-qualified class name of the narrow
     * capability contract this middleware probes
     * (`SupportsRoles` / `SupportsPermissions`).
     *
     * @return class-string
     */
    abstract protected function requiredContract(): string;

    /**
     * Test whether the supplied principal satisfies a single
     * needle (role name, permission string, …).
     *
     * @param  object  $principal
     * @param  string  $needle
     * @return bool
     */
    abstract protected function matches(object $principal, string $needle): bool;

    /**
     * Human-readable message attached to the `AccessDenied`
     * response when no needle matches.
     *
     * @return string
     */
    abstract protected function rejectionMessage(): string;

    /**
     * Flatten pipe-separated arguments so a single middleware
     * declaration like `role:admin|editor` behaves identically to
     * the native Laravel `role:admin,editor` form. Shared across
     * every concrete subclass — the separator rules do not vary
     * by capability.
     *
     * @param  array<int, string>  $arguments
     * @return array<int, string>
     */
    private static function expand(array $arguments): array
    {
        $needles = [];

        foreach ($arguments as $argument) {
            foreach (\explode('|', $argument) as $candidate) {
                $candidate = \trim($candidate);

                if ($candidate !== '') {
                    $needles[] = $candidate;
                }
            }
        }

        return $needles;
    }
}
