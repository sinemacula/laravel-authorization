<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Subject;

/**
 * The default subject resolver: Laravel's authenticated user.
 *
 * Reads the user from Laravel's default guard (`auth.defaults.guard`, which
 * `Auth::shouldUse()` changes), the guard Laravel's Gate takes its user from,
 * so the package's middleware, Blade directives and facade decide about the
 * same user as `@can` and `can:`. The user is both the subject and its
 * identity, no tenant is active, and the guard's name is the application. A
 * request with no user has no subject.
 *
 * The subject's session is the current request's session id only when that
 * session signed in that very user: the guard is a `SessionGuard` using the
 * request's session, once it has started, and the session's login key names the
 * user, compared strictly as strings. The user is the one `resolve()` reads, or
 * the same user handed to `forUser()`. A user set on the guard without the
 * session (through `once()`, `onceUsingId()`, `onceBasic()` or `setUser()`), a
 * user a token or request guard returns, any other user, and every user outside
 * a session (a console command, a queued job, a stateless request), has none,
 * so no authentication requirement is met for it (N34). The request is read
 * from the container on every resolution, never kept.
 *
 * A deployment that wants another guard binds the contract to an instance built
 * with that guard's name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuthGuardSubjectResolver implements SubjectResolver
{
    /**
     * Create a new resolver instance.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string|null  $guard
     * @param  \Illuminate\Contracts\Container\Container|null  $container
     */
    public function __construct(

        /** Laravel auth factory the user is read from. */
        private AuthFactory $auth,

        /** Configuration the default guard's name is read from. */
        private Config $config,

        /** Guard to read; null reads Laravel's default guard. */
        private ?string $guard = null,

        /** Container the current request, and its session, is read from; null reads no session. */
        private ?Container $container = null,
    ) {}

    /**
     * Resolve the authenticated user as the subject, or null when no user is
     * signed in.
     *
     * @return \SineMacula\Laravel\Authorization\Subject|null
     */
    #[\Override]
    public function resolve(): ?Subject
    {
        $guard = $this->auth->guard($this->guardName());
        $user  = $guard->user();

        return $user === null ? null : $this->subjectOf($user, $this->sessionFor($user, $guard));
    }

    /**
     * Make the given user the subject and its identity, with no tenant and the
     * guard's name as the application, and the request's session when the user
     * is the one signed in on the guard and the session signed it in.
     *
     * @param  object  $user
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function forUser(object $user): Subject
    {
        $guard = $this->requestSession() !== null ? $this->auth->guard($this->guardName()) : null;

        return $this->subjectOf($user, $guard !== null && $user === $guard->user() ? $this->sessionFor($user, $guard) : null);
    }

    /**
     * Make the user the subject and its identity, with no tenant, the guard's
     * name as the application, and the session given.
     *
     * @param  object  $user
     * @param  string|null  $session
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    private function subjectOf(object $user, ?string $session): Subject
    {
        $guard = $this->guardName();

        return new Subject(
            subject: $user,
            identity: $user,
            tenant: null,
            application: $guard,
            guard: $guard,
            session: $session,
        );
    }

    /**
     * Return the id of the current request's session when that session signed
     * the user in on the guard, or null otherwise: the guard is a session guard
     * using the request's session, and the session's login key names the user,
     * compared strictly as strings.
     *
     * @param  object  $user
     * @param  \Illuminate\Contracts\Auth\Guard  $guard
     * @return string|null
     */
    private function sessionFor(object $user, Guard $guard): ?string
    {
        $session = $this->requestSession();

        if ($session === null || !$guard instanceof SessionGuard || !$user instanceof Authenticatable || $guard->getSession()->getId() !== $session->getId()) {
            return null;
        }

        return self::isSameIdentifier($session->get($guard->getName()), $user->getAuthIdentifier()) ? $session->getId() : null;
    }

    /**
     * Determine whether the identifier the session holds and the user's own are
     * the same, compared strictly as strings: each must be a string or an
     * integer.
     *
     * @param  mixed  $held
     * @param  mixed  $identifier
     * @return bool
     */
    private static function isSameIdentifier(mixed $held, mixed $identifier): bool
    {
        return (\is_string($held) || \is_int($held)) && (\is_string($identifier) || \is_int($identifier)) && (string) $held === (string) $identifier;
    }

    /**
     * Return the current request's session, or null when there is no request,
     * it has no session, or the session has not started.
     *
     * @return \Illuminate\Contracts\Session\Session|null
     */
    private function requestSession(): ?Session
    {
        $request = $this->container !== null   && $this->container->bound('request') ? $this->container->make('request') : null;
        $session = $request instanceof Request && $request->hasSession() ? $request->session() : null;

        return $session !== null && $session->isStarted() ? $session : null;
    }

    /**
     * Return the name of the guard read: the one given at construction, or
     * Laravel's default guard. Null when neither names one.
     *
     * @return string|null
     */
    private function guardName(): ?string
    {
        $guard = $this->guard ?? $this->config->get('auth.defaults.guard');

        return \is_string($guard) && $guard !== '' ? $guard : null;
    }
}
