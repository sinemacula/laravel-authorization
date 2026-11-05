<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Http\Middleware;

use Illuminate\Http\Request;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Support\CheckArguments;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;

/**
 * Route middleware that admits a request when the subject holds any of the
 * listed roles.
 *
 * Wired under the `role` alias by the service provider, as `role:admin|editor`
 * or, limited to the roles of one guard and the guard-agnostic ones,
 * `role:admin|editor,web`. A role is not an action, so this is a membership
 * check of the roles the subject holds and its identity holds (see
 * `SubjectGrants`), which sees only the roles of the subject's tenant and the
 * platform; policies do not apply to it. To decide an action, use the
 * `permission` or `authorize` middleware. For every one of several roles, chain
 * the middleware: `->middleware(['role:admin', 'role:oncall'])`.
 *
 * A subject that cannot hold roles holds none, and is denied. A subject that is
 * inactive, or whose identity is, is denied with the `subject_inactive` reason
 * code. Any other denial carries the `implicit_deny` reason code and the
 * `role_required` message; since no action was decided, it records no decision
 * and fires no `AuthorizationFailed` event. A guard that is also the name of a
 * role is refused, since `role:editor,admin` may mean either role; write it as
 * `guard=admin`.
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
     * @param  non-empty-list<string>  $names
     * @param  string|null  $option
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    #[\Override]
    protected function authorize(Request $request, array $names, ?string $option): void
    {
        $guard   = CheckArguments::guard($option);
        $subject = $this->subject();

        if (SubjectGrants::isInactive($subject)) {
            throw $this->denial(DecisionReason::SUBJECT_INACTIVE);
        }

        foreach ($names as $role) {
            if (SubjectGrants::holdsRole($subject, $role, $guard)) {
                return;
            }
        }

        throw $this->denial(DecisionReason::IMPLICIT_DENY, AuthorizationException::ROLE_REQUIRED_KEY);
    }
}
