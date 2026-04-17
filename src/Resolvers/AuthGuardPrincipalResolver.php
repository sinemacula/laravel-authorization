<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;

/**
 * Principal resolver that reads from Laravel's standard auth
 * factory.
 *
 * The shipped default is `NullPrincipalResolver` (anonymous-safe,
 * zero auth coupling). Consumers wiring the package onto a
 * standard Laravel auth stack point
 * `authorization.principal_resolver` at this class to let the
 * authorization engine resolve "the current principal" from
 * `Auth::guard($name)->user()` — the four-line boilerplate every
 * app would otherwise write.
 *
 * The guard name defaults to `authorization.defaults.guard` and
 * can be overridden at construction for multi-guard deployments
 * that want to pin the authorization resolution to a specific
 * guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuthGuardPrincipalResolver implements PrincipalResolver
{
    /**
     * Create a new resolver instance.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @param  string|null  $guard
     */
    public function __construct(

        /** Laravel auth factory consulted on every resolution. */
        private readonly AuthFactory $auth,

        /** Guard name to resolve; null falls back to the configured default. */
        private readonly ?string $guard = null,

    ) {}

    /**
     * @return object|null
     */
    #[\Override]
    public function resolve(): ?object
    {
        $guard = $this->guard ?? self::defaultGuard();

        $user = $this->auth->guard($guard)->user();

        return $user instanceof \Illuminate\Contracts\Auth\Authenticatable
            ? $user
            : null;
    }

    /**
     * Resolve the configured default guard, falling back to
     * `'web'` when config is unavailable.
     *
     * @return string
     */
    private static function defaultGuard(): string
    {
        if (!\function_exists('config')) {
            return 'web'; // @codeCoverageIgnore
        }

        /** @var string|null $guard */
        $guard = config('authorization.defaults.guard');

        return \is_string($guard) && $guard !== '' ? $guard : 'web';
    }
}
