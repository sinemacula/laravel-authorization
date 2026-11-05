<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository as Config;
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
     */
    public function __construct(

        /** Laravel auth factory the user is read from. */
        private AuthFactory $auth,

        /** Configuration the default guard's name is read from. */
        private Config $config,

        /** Guard to read; null reads Laravel's default guard. */
        private ?string $guard = null,
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
        $user = $this->auth->guard($this->guardName())->user();

        return $user === null ? null : $this->forUser($user);
    }

    /**
     * Make the given user the subject and its identity, with no tenant and the
     * guard's name as the application.
     *
     * @param  object  $user
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function forUser(object $user): Subject
    {
        $guard = $this->guardName();

        return new Subject(
            subject: $user,
            identity: $user,
            tenant: null,
            application: $guard,
            guard: $guard,
        );
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
