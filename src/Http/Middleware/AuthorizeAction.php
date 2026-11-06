<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Http\Middleware;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Subject;
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
     * Create a new middleware instance.
     *
     * @param  \Illuminate\Contracts\Translation\Translator|null  $translator
     * @param  \Illuminate\Contracts\Events\Dispatcher|null  $events
     */
    public function __construct(

        // Translator that words a denial's message; null keeps English.
        ?Translator $translator = null,

        /** Event dispatcher that reports a refusal; null disables. */
        private readonly ?Dispatcher $events = null,
    ) {
        parent::__construct($translator);
    }

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
     */
    #[\Override]
    protected function authorize(Request $request, array $names, ?string $option): void
    {
        $resource = $option === null ? null : self::resourceOf($request, $option);
        $subject  = $this->subject();

        if ($resource === false) {
            throw $this->refusal($subject, $names[\array_key_last($names)]);
        }

        $this->authorizeAny($names, $resource);
    }

    /**
     * Refuse the action on a resource that cannot be identified, as a denied
     * list is refused: the implicit deny is recorded for the last action and
     * fires the `AuthorizationFailed` event once.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private function refusal(Subject $subject, string $action): AuthorizationException
    {
        $decision = self::manager()->refuseUnidentifiedResource($action);

        $this->events?->dispatch(new AuthorizationFailed($subject->subject, $action, null, [], $decision));

        return $this->denial(DecisionReason::RESOURCE_UNRESOLVED);
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
