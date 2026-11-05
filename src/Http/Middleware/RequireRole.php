<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Http\Middleware;

use Illuminate\Http\Request;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Support\CheckArguments;

/**
 * Route middleware that admits a request when the subject holds any of the
 * listed roles.
 *
 * Wired under the `role` alias by the service provider, as `role:admin|editor`
 * or, limited to the roles of one guard and the guard-agnostic ones,
 * `role:admin|editor,web`. A role is not an action, so this is a membership
 * check through the subject's `hasRole()`, which sees only the roles of the
 * subject's tenant and the platform; policies do not apply to it. To decide an
 * action, use the `permission` or `authorize` middleware. For every one of
 * several roles, chain the middleware:
 * `->middleware(['role:admin', 'role:oncall'])`.
 *
 * A subject that cannot hold roles holds none, and is denied.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RequireRole extends AbstractAuthorizationMiddleware
{
    /**
     * Admit the request when the subject holds any listed role.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $names
     * @param  string|null  $option
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    #[\Override]
    protected function authorize(Request $request, string $names, ?string $option): void
    {
        $guard     = CheckArguments::guard($option);
        $principal = $this->subject()->subject;

        if ($principal instanceof SupportsRoles) {
            foreach (CheckArguments::names($names) as $role) {
                if ($principal->hasRole($role, $guard)) {
                    return;
                }
            }
        }

        throw $this->denial(DecisionReason::IMPLICIT_DENY, AuthorizationException::ROLE_REQUIRED_KEY);
    }
}
