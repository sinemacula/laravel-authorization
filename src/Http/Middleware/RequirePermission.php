<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Http\Middleware;

use Illuminate\Http\Request;
use SineMacula\Laravel\Authorization\Support\CheckArguments;

/**
 * Route middleware that admits a request when the full decision allows any of
 * the listed actions for the subject, with no resource.
 *
 * Wired under the `permission` alias by the service provider, as
 * `permission:posts:update|posts:manage`. Each action is decided by the
 * authorization manager as `Authorization::can()` and the Gate decide it:
 * policies, an explicit deny, the permissions held and the subject's tenant. An
 * explicit deny wins over a held permission, and a policy allow admits without
 * one. For every one of several actions, chain the middleware:
 * `->middleware(['permission:posts:update', 'permission:posts:publish'])`.
 *
 * The decision takes no guard, so a guard argument
 * (`permission:posts:update,web`) is refused rather than ignored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RequirePermission extends AbstractAuthorizationMiddleware
{
    /**
     * Admit the request when any listed action is allowed.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  non-empty-list<string>  $names
     * @param  string|null  $option
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    #[\Override]
    protected function authorize(Request $request, array $names, ?string $option): void
    {
        CheckArguments::refuseGuard('permission', $option);

        $this->subject();
        $this->authorizeAny($names, null);
    }
}
