<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Registrars;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Gate;
use SineMacula\Laravel\Authorization\Config\SwitchConfigValidator;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Support\DeclaredAbilities;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;

/**
 * Make the package the authority of Laravel's Gate (AUTHZ-9.1) through a single
 * `Gate::before` hook.
 *
 * The hook answers every ability whose exact name the declared catalogue holds
 * (see `DeclaredAbilities`): the permissions the configured enums and providers
 * declare, and the package's own. For those it returns the decision of
 * `check()`, true for an allow and false for a deny, and both stand: Laravel
 * stops at the first before-callback that answers, so no `Gate::define`
 * callback, Laravel policy class or after-callback the application registers
 * can override either. For every other ability, permission rows that exist only
 * in the database among them, it answers null, and Laravel decides it
 * unchanged.
 *
 * Laravel runs the before-callbacks in the order they were registered, and the
 * first that answers wins. The service provider registers the hook first thing
 * in its boot, so an application's `Gate::before` registered later never
 * pre-empts it; one registered before the package boots still can.
 *
 * The Gate's user is translated into the subject through `forUser()`, and a
 * guest (no user) is decided as no subject, which denies, never as the subject
 * of the current request.
 *
 * With `authorization.gate.enabled` false nothing is registered and the Gate is
 * left to Laravel entirely.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GateRegistrar
{
    /**
     * Create a new registrar instance.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     */
    public function __construct(

        /** Framework container consulted for config and bindings. */
        private Application $app,
    ) {}

    /**
     * Determine whether the configuration turns the Gate hook on: when
     * `authorization.gate.enabled` is true or left out, it does, and when it is
     * false, it does not. Any other value is refused, never read as either.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function isEnabled(ConfigRepository $config): bool
    {
        return SwitchConfigValidator::isEnabled('gate', $config);
    }

    /**
     * Register the Gate hook, and the declared abilities it reads, scoped to
     * the request or job, unless the configuration turns the hook off.
     *
     * The hook answers an ability the package declares for the Gate's user,
     * with whether `check()` allows it, and leaves every other ability to
     * Laravel by answering null.
     *
     * @return void
     */
    public function register(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app['config'];

        if (!self::isEnabled($config)) {
            return;
        }

        $app = $this->app;

        $app->scoped(DeclaredAbilities::class);

        // The declared abilities are bound just above, so the hook resolves
        // them directly: it never runs without them.
        Gate::before(static function (?object $user, string $ability, array $arguments) use ($app): ?bool {
            if (!$app->make(DeclaredAbilities::class)->holds($ability)) {
                return null;
            }

            [$resource, $context] = self::translateGateArguments($arguments);

            // The subject resolver translates the Gate's user into the subject;
            // a guest is no subject, so the check denies.
            return Authorization::forUser($user)->can($ability, $resource, $context);
        });
    }

    /**
     * Translate the arguments Laravel hands to the Gate hook into the
     * `(resource, context)` pair the authorization manager accepts. String keys
     * and string-keyed arrays merge into the caller's values, which the check
     * holds under `input` and nowhere else (`Gate::allows('posts:update',
     * [$post, 'request' => [...]])` supplies `input.request`, never `request`);
     * every other argument names the resource. Laravel takes an argument array
     * as the list of arguments, so `Gate::allows('posts:update', ['post', 42])`
     * arrives as two arguments, which name the `(type, id)` pair they spell;
     * one argument names the resource it is, and any other set of arguments
     * names no resource the check can identify (false), so none is ever
     * silently dropped.
     *
     * @param  array<int|string, mixed>  $arguments
     * @return array{0: false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null, 1: array<string, mixed>}
     */
    private static function translateGateArguments(array $arguments): array
    {
        $resource = [];
        $context  = [];

        foreach ($arguments as $key => $value) {
            if (\is_string($key)) {
                $context[$key] = $value;
            } elseif (\is_array($value) && !\array_is_list($value)) {
                $context = \array_merge($context, $value);
            } else {
                $resource[] = $value;
            }
        }

        /** @var array<string, mixed> $context */
        return [self::resourceOf($resource), $context];
    }

    /**
     * Return the reference to the resource the Gate's resource arguments name:
     * none for no argument, the argument's own for one, the pair's for two, and
     * false for more, which no resource is.
     *
     * @param  list<mixed>  $arguments
     * @return false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null
     */
    private static function resourceOf(array $arguments): false|ResourceReference|null
    {
        return match (\count($arguments)) {
            0       => null,
            1       => ResourceReferences::of($arguments[0]),
            default => ResourceReferences::of($arguments),
        };
    }
}
