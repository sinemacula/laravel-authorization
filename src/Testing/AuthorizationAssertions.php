<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Testing;

use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Contracts\SupportsPermissions;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
use SineMacula\Laravel\Authorization\Facades\Authorization;

/**
 * PHPUnit assertion trait for consumer test suites.
 *
 * Provides convenience assertions that delegate to the authorization manager's
 * evaluation surface. The assertion methods require the using class to extend
 * `PHPUnit\Framework\TestCase`, which supplies the `assertTrue` / `assertFalse`
 * static entry points. The `actingAsIdentity` helper intentionally does not
 * depend on the TestCase base — it can be composed into any consumer utility
 * and falls back to the global `app()` helper when `$this->app` is not
 * available.
 *
 * @method static void assertTrue(bool $condition, string $message = '')
 * @method static void assertFalse(bool $condition, string $message = '')
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait AuthorizationAssertions
{
    /**
     * Assert that the principal is allowed to perform the action.
     *
     * On failure, the evaluation trace is included in the message so the
     * developer can immediately see why the check was denied.
     *
     * @param  object  $principal
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return void
     */
    public function assertCan(object $principal, string $action, ?string $resource = null, array $context = []): void
    {
        $result = Authorization::for($principal)->evaluate($action, $resource, $context);

        self::assertTrue(
            $result->allowed,
            \sprintf(
                "Failed asserting that the principal can perform '%s'%s.\nEvaluation trace:\n%s",
                $action,
                $resource !== null ? " on resource '{$resource}'" : '',
                $result->explain(),
            ),
        );
    }

    /**
     * Assert that the principal is denied the action.
     *
     * On failure, the evaluation trace is included in the message so the
     * developer can see why the check was unexpectedly allowed.
     *
     * @param  object  $principal
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return void
     */
    public function assertCannot(object $principal, string $action, ?string $resource = null, array $context = []): void
    {
        $result = Authorization::for($principal)->evaluate($action, $resource, $context);

        self::assertFalse(
            $result->allowed,
            \sprintf(
                "Failed asserting that the principal cannot perform '%s'%s.\nEvaluation trace:\n%s",
                $action,
                $resource !== null ? " on resource '{$resource}'" : '',
                $result->explain(),
            ),
        );
    }

    /**
     * Assert that the principal holds the given role.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\SupportsRoles  $principal
     * @param  string  $role
     * @return void
     */
    public function assertHasRole(SupportsRoles $principal, string $role): void
    {
        self::assertTrue(
            $principal->hasRole($role),
            \sprintf(
                'Failed asserting that the principal has role \'%s\'. Assigned roles: [%s].',
                $role,
                \implode(', ', $principal->getRoles()),
            ),
        );
    }

    /**
     * Assert that the principal holds the given permission (direct or
     * role-inherited, including wildcard matching).
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\SupportsPermissions  $principal
     * @param  string  $permission
     * @return void
     */
    public function assertHasPermission(SupportsPermissions $principal, string $permission): void
    {
        self::assertTrue(
            $principal->hasPermission($permission),
            \sprintf(
                'Failed asserting that the principal has permission \'%s\'. Held permissions: [%s].',
                $permission,
                \implode(', ', $principal->getPermissions()),
            ),
        );
    }

    /**
     * Swap the principal resolver for the duration of the test so that
     * `Authorization::can(...)` (without `for()`) uses the supplied principal.
     *
     * Works with both Orchestra Testbench (`$this->app`) and bare Laravel
     * (`app()`).
     *
     * @param  object  $principal
     * @return void
     */
    public function actingAsIdentity(object $principal): void
    {
        $resolver = new class ($principal) implements PrincipalResolver {
            /**
             * @param  object  $principal
             */
            public function __construct(private readonly object $principal) {}

            /**
             * @return object|null
             */
            #[\Override]
            public function resolve(): ?object
            {
                return $this->principal;
            }
        };

        $container = $this->resolveTestingContainer();

        $container->instance(PrincipalResolver::class, $resolver);

        // Rebuild the manager singleton so it picks up the new
        // resolver. Forgetting both the alias and the concrete class
        // ensures the next resolve rebuilds from scratch.
        if ($container->bound('authorization')) {
            $container->forgetInstance('authorization');
            $container->forgetInstance(AuthorizationManager::class);
        }

        // Clear the facade's resolved-instance cache so the next
        // static call goes back through the container.
        Authorization::clearResolvedInstance('authorization');
    }

    /**
     * Resolve the Laravel container to bind the test's principal resolver into.
     * Prefers the `$app` property when the consuming class declares one
     * (Laravel/Testbench `TestCase`), falling back to the global container
     * singleton for bare consumers.
     *
     * `get_object_vars($this)` reads the using class's own properties without a
     * static `$this->app` access — the direct access would be flagged by
     * PHPStan as either always-true or always-false depending on the concrete
     * using class, and reflection was flagged by radarlint as an accessibility
     * bypass.
     *
     * @return \Illuminate\Container\Container
     */
    private function resolveTestingContainer(): \Illuminate\Container\Container
    {
        /** @var array<string, mixed> $vars */
        $vars = \get_object_vars($this);
        $app  = $vars['app'] ?? null;

        if ($app instanceof \Illuminate\Container\Container) {
            return $app;
        }

        return \Illuminate\Container\Container::getInstance();
    }
}
