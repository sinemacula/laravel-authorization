<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Http\Middleware;

use Illuminate\Http\Request;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Support\CheckArguments;
use SineMacula\Laravel\Authorization\Support\ResourceIdentifier;

/**
 * Route middleware that admits a request when the full decision allows an
 * action on the model a route parameter binds.
 *
 * Wired under the `authorize` alias by the service provider, as
 * `authorize:posts:update,post`. The parameter's bound model, or its raw value
 * when nothing binds it, is the resource, converted as the Gate converts its
 * argument: a resource names itself, a model is `morphClass:key` and a string
 * is used as given. A value that cannot be identified, such as an unsaved
 * model, or a parameter the route does not carry, denies. Without a parameter
 * (`authorize:reports:export`) the check is about no resource. Several actions
 * may be listed with `|`; any one allowed admits the request.
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
     * @param  string  $names
     * @param  string|null  $option
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    #[\Override]
    protected function authorize(Request $request, string $names, ?string $option): void
    {
        $actions  = CheckArguments::names($names);
        $resource = $option === null ? null : self::resourceOf($request, $option);

        $this->subject();

        if ($resource !== false) {
            $this->authorizeAny($actions, $resource);

            return;
        }

        foreach ($actions as $action) {
            self::manager()->refuseUnidentifiedResource($action);
        }

        throw $this->denial(DecisionReason::IMPLICIT_DENY);
    }

    /**
     * Return the resource identifier of the route parameter's value, or false
     * when the route carries no such parameter or its value cannot be
     * identified.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $parameter
     * @return false|string
     */
    private static function resourceOf(Request $request, string $parameter): false|string
    {
        return ResourceIdentifier::of($request->route($parameter)) ?? false;
    }
}
