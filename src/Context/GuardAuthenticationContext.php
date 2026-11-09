<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Context;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\ScopeInvariant;

/**
 * The default authentication context: what Laravel knows (AUTHZ-13.2).
 *
 * Supplies the `authentication` namespace alone: the name of the guard read
 * (`guard`), and, when a user is signed in on it, the user's key (`user_id`, as
 * a string) and morph type (`user_type`, the morph alias of an Eloquent user,
 * the class name of any other). With nobody signed in only `guard` is present,
 * and with no guard named either the namespace is absent. Nothing is ever read
 * from what the caller passes.
 *
 * The guard read is Laravel's default guard (`auth.defaults.guard`), the one
 * the default subject resolver reads too, unless one is given at construction.
 *
 * It is marked `ScopeInvariant`: it reads the request alone, never the record a
 * check is about, so `whereAuthorized()` reads it once for a query.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GuardAuthenticationContext implements AuthenticationContext, ScopeInvariant
{
    /** @var string The namespace the context supplies. */
    public const string NAMESPACE = 'authentication';

    /**
     * Create a new guard authentication context.
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
     * Return the namespaces the context supplies: `authentication` alone.
     *
     * @return list<string>
     */
    #[\Override]
    public function namespaces(): array
    {
        return [self::NAMESPACE];
    }

    /**
     * Return no assurance key names of its own: the package's fixed names are
     * the only assurance keys of `authentication`.
     *
     * @return list<string>
     */
    #[\Override]
    public function assuranceKeys(): array
    {
        return [];
    }

    /**
     * Return the guard's name and the signed-in user's key and morph type,
     * under `authentication`. With no guard named no user is read, and the
     * namespace is absent.
     *
     * @return array<string, array<string, mixed>>
     */
    #[\Override]
    public function values(): array
    {
        $guard  = $this->guardName();
        $user   = $guard === null ? null : $this->auth->guard($guard)->user();
        $values = ($guard === null ? [] : ['guard' => $guard]) + ($user === null ? [] : self::userValues($user));

        return $values === [] ? [] : [self::NAMESPACE => $values];
    }

    /**
     * Return the user's key, as a string, and morph type. A key that is not a
     * scalar is left out.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return array<string, string>
     */
    private static function userValues(Authenticatable $user): array
    {
        $key = $user->getAuthIdentifier();

        return (\is_scalar($key) ? ['user_id' => (string) $key] : [])
            + ['user_type' => $user instanceof Model ? self::morphClassOf($user) : $user::class];
    }

    /**
     * Return an Eloquent user's morph type: its morph alias, or its class name
     * when it has none.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $user
     * @return string
     */
    private static function morphClassOf(Model $user): string
    {
        return $user->getMorphClass();
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
