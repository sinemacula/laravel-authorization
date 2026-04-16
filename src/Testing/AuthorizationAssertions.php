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
 * Provides convenience assertions that delegate to the authorization
 * manager's evaluation surface. Usable without Orchestra Testbench
 * when a Laravel application container is available via `app()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait AuthorizationAssertions
{
    /**
     * Assert that the principal is allowed to perform the action.
     *
     * On failure, the evaluation trace is included in the message so
     * the developer can immediately see why the check was denied.
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
     * On failure, the evaluation trace is included in the message so
     * the developer can see why the check was unexpectedly allowed.
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
     * @param  object  $principal
     * @param  string  $role
     * @return void
     */
    public function assertHasRole(object $principal, string $role): void
    {
        self::assertInstanceOf(SupportsRoles::class, $principal, 'Principal does not implement SupportsRoles.');

        // @var \SineMacula\Laravel\Authorization\Contracts\SupportsRoles $principal
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
     * @param  object  $principal
     * @param  string  $permission
     * @return void
     */
    public function assertHasPermission(object $principal, string $permission): void
    {
        self::assertInstanceOf(SupportsPermissions::class, $principal, 'Principal does not implement SupportsPermissions.');

        // @var \SineMacula\Laravel\Authorization\Contracts\SupportsPermissions $principal
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
     * Swap the principal resolver for the duration of the test so
     * that `Authorization::can(...)` (without `for()`) uses the
     * supplied principal.
     *
     * Works with both Orchestra Testbench (`$this->app`) and bare
     * Laravel (`app()`).
     *
     * @param  object  $principal
     * @return void
     */
    public function actingAsIdentity(object $principal): void
    {
        $resolver = new class ($principal) implements PrincipalResolver {
            public function __construct(private readonly object $principal) {}

            public function resolve(): ?object
            {
                return $this->principal;
            }
        };

        $container = \property_exists($this, 'app') && $this->app !== null
            ? $this->app
            : app();

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
}
