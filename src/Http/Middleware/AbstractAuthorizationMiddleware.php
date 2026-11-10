<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Http\Middleware;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\CheckArguments;
use SineMacula\Laravel\Authorization\Support\Messages;

/**
 * Shared template method for the shipped authorization middleware.
 *
 * Every middleware takes at most two arguments: the names to check, separated
 * by `|`, and one option (a guard, or a route parameter). A list that names
 * nothing, or a third argument, is a mistake in the route and is refused. A
 * request without a subject is unauthenticated (401), with the translated
 * `unauthenticated` line; a denial throws the package's
 * `AuthorizationException`, which Laravel renders as a 403 with the reason code
 * and the translated `denied` line, and an `insufficient_authentication` denial
 * throws `InsufficientAuthenticationException`, which the application maps to
 * its step-up response (a 403 when it does not).
 *
 * Run it after authentication and after any step-up middleware, so a request
 * that is not signed in, or not signed in strongly enough, is answered by those
 * before it is denied here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract class AbstractAuthorizationMiddleware
{
    /**
     * Create a new middleware instance.
     *
     * @param  \Illuminate\Contracts\Translation\Translator|null  $translator
     */
    public function __construct(

        /** Translator that words the messages it throws; null keeps English. */
        private readonly ?Translator $translator = null,
    ) {}

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): mixed  $next
     * @param  string  ...$arguments
     * @return mixed
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public function handle(Request $request, \Closure $next, string ...$arguments): mixed
    {
        self::refuseExtraArguments($arguments);

        $this->authorize($request, self::namesOf($arguments[0] ?? ''), $arguments[1] ?? null);

        return $next($request);
    }

    /**
     * Authorise the request, or throw when it is denied.
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
    abstract protected function authorize(Request $request, array $names, ?string $option): void;

    /**
     * Return the subject the request is about, or throw when there is none.
     *
     * The exception's message is the translated `unauthenticated` line, or
     * Laravel's English `Unauthenticated.` without a translator or a line.
     *
     * @return \SineMacula\Laravel\Authorization\Subject
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    protected function subject(): Subject
    {
        return self::manager()->currentSubject() ?? throw new AuthenticationException(Messages::line(Messages::UNAUTHENTICATED, $this->translator) ?? 'Unauthenticated.');
    }

    /**
     * Admit the request when the full decision allows any of the actions.
     *
     * Each action is decided in turn and the first one allowed admits the
     * request. The last is authorised, so its denial is recorded, fires the
     * `AuthorizationFailed` event and throws with its reason code, as
     * `Authorization::authorize()` does.
     *
     * @param  non-empty-list<string>  $actions
     * @param  mixed  $resource
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    protected function authorizeAny(array $actions, mixed $resource): void
    {
        $manager = self::manager();
        $last    = \array_pop($actions);

        foreach ($actions as $action) {
            if ($manager->can($action, $resource)) {
                return;
            }
        }

        $manager->authorize($last, $resource);
    }

    /**
     * Build the denial for the reason, worded by the generic `denied` line.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason  $reason
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    protected function denial(DecisionReason $reason): AuthorizationException
    {
        return AuthorizationException::translated($reason, $this->translator);
    }

    /**
     * Return the authorization manager the facade resolves.
     *
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    protected static function manager(): AuthorizationManager
    {
        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager */
        return Authorization::getFacadeRoot();
    }

    /**
     * Return the names the first argument lists, refusing a list that names
     * none.
     *
     * @param  string  $names
     * @return non-empty-list<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    private static function namesOf(string $names): array
    {
        $listed = CheckArguments::names($names);

        if ($listed === []) {
            throw InvalidCheckArgumentException::noNames(static::class);
        }

        return $listed;
    }

    /**
     * Refuse more than the two arguments every middleware takes.
     *
     * @param  array<array-key, string>  $arguments
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    private static function refuseExtraArguments(array $arguments): void
    {
        if (\count($arguments) > 2) {
            throw InvalidCheckArgumentException::tooManyArguments(static::class, \count($arguments));
        }
    }
}
