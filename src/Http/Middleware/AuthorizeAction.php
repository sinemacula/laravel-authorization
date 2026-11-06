<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Http\Middleware;

use Illuminate\Http\Request;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;

/**
 * Route middleware that admits a request when the full decision allows an
 * action on the model a route parameter binds.
 *
 * Wired under the `authorize` alias by the service provider, as
 * `authorize:posts:update,post`. The parameter's bound model, or its raw value
 * when nothing binds it, is the resource, referenced as every check references
 * it (`ResourceReferences`): a resource names itself, a model is `type:id` in
 * its tenant, and a string is used as given. A value that cannot be identified,
 * such as an unsaved model or a value holding a NUL byte, or a parameter the
 * route does not carry, denies as `resource_unresolved`. Without a parameter
 * (`authorize:reports:export`) the check is about no resource. Several actions
 * may be listed with `|`; any one allowed admits the request.
 *
 * The service provider places this middleware right after Laravel's
 * `SubstituteBindings` in the middleware priority, so it decides on the bound
 * model wherever the route declares it, as Laravel's `can` middleware does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuthorizeAction extends AbstractAuthorizationMiddleware
{
    /**
     * Admit the request when any listed action is allowed on the parameter's
     * resource.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  non-empty-list<string>  $names
     * @param  string|null  $option
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    #[\Override]
    protected function authorize(Request $request, array $names, ?string $option): void
    {
        $this->subject();

        // A parameter the route does not carry is a resource that cannot be
        // identified, never a check about no resource. A parameter no binding
        // turned into a model is the caller's own text: an opaque identifier,
        // never read as a class name. The resource is resolved once for every
        // listed action.
        $value = $option === null ? null : $request->route($option) ?? false;

        $this->authorizeAny($names, \is_string($value) ? new ResourceReference($value) : ResourceReferences::of($value));
    }
}
