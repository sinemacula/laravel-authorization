<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Testing\Concerns;

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Access\Gate as GateContract;
use Illuminate\Support\Facades\Gate;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\SupportsPermissions;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;

/**
 * PHPUnit assertion trait for consumer test suites.
 *
 * Provides convenience assertions that delegate to the authorization manager's
 * evaluation surface. The assertion methods require the using class to extend
 * `PHPUnit\Framework\TestCase`, which supplies the `assertTrue` / `assertFalse`
 * static entry points. The `actingAsIdentity` and `actingAsSubject` helpers
 * intentionally do not depend on the TestCase base — they can be composed into
 * any consumer utility and fall back to the global container when `$this->app`
 * is not available.
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
     * @param  mixed  $resource
     * @param  array<string, mixed>  $context
     * @return void
     */
    public function assertCan(object $principal, string $action, mixed $resource = null, array $context = []): void
    {
        $decision = Authorization::for($principal)->check($action, $resource, $context);

        self::assertTrue(
            $decision->isAllowed(),
            \sprintf(
                "Failed asserting that the principal can perform '%s'%s.\nDecision:\n%s",
                $action,
                self::describeResource($resource),
                $decision->explain()->toText(),
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
     * @param  mixed  $resource
     * @param  array<string, mixed>  $context
     * @return void
     */
    public function assertCannot(object $principal, string $action, mixed $resource = null, array $context = []): void
    {
        $decision = Authorization::for($principal)->check($action, $resource, $context);

        self::assertFalse(
            $decision->isAllowed(),
            \sprintf(
                "Failed asserting that the principal cannot perform '%s'%s.\nDecision:\n%s",
                $action,
                self::describeResource($resource),
                $decision->explain()->toText(),
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
     * Swap the subject resolver for the duration of the test so that
     * `Authorization::can(...)` (without `for()`), the package's middleware and
     * Blade directives decide about the supplied identity, in the supplied
     * tenant or in none, and make the identity the user Laravel's Gate hands
     * over, so `Gate::allows()`, `@can` and `can:` decide about it too.
     *
     * Works with both Orchestra Testbench (`$this->app`) and bare Laravel
     * (`app()`).
     *
     * @param  object  $identity
     * @param  object|null  $tenant
     * @return void
     */
    public function actingAsIdentity(object $identity, ?object $tenant = null): void
    {
        $this->actingAsSubject(new Subject($identity, $identity, $tenant));
    }

    /**
     * Swap the subject resolver for the duration of the test so that every
     * check without a named subject is about the supplied subject, in its
     * tenant and application, and make the subject's identity, or its principal
     * when it has none, the user Laravel's Gate hands over. `Gate::allows()`,
     * `@can` and `can:` then decide about the subject, as the facade does.
     * `Gate::forUser()` with the subject's principal or identity decides about
     * the subject too; any other user is decided about in that same tenant and
     * application.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return void
     */
    public function actingAsSubject(Subject $subject): void
    {
        $resolver = new class ($subject) implements SubjectResolver {
            /**
             * @param  \SineMacula\Laravel\Authorization\Subject  $subject
             */
            public function __construct(

                /** The subject slotted for resolution. */
                private readonly Subject $subject,
            ) {}

            /**
             * @return \SineMacula\Laravel\Authorization\Subject
             */
            #[\Override]
            public function resolve(): Subject
            {
                return $this->subject;
            }

            /**
             * Return the acting subject, its session included, for its own
             * principal or identity, since the Gate hands over the signed-in
             * user, and any other user as a subject of its own in the same
             * request.
             *
             * @param  object  $user
             * @return \SineMacula\Laravel\Authorization\Subject
             */
            #[\Override]
            public function forUser(object $user): Subject
            {
                if ($user === $this->subject->identity || $user === $this->subject->subject) {
                    return $this->subject;
                }

                return $this->subject->withSubject($user);
            }
        };

        $container = $this->resolveTestingContainer();

        $container->instance(SubjectResolver::class, $resolver);

        // Rebuild the manager so it picks up the new resolver. Forgetting both
        // the alias and the concrete class ensures the next resolve rebuilds
        // from scratch.
        if ($container->bound('authorization')) {
            $container->forgetInstance('authorization');
            $container->forgetInstance(AuthorizationManager::class);
        }

        // Clear the facade's resolved-instance cache so the next static call
        // goes back through the container.
        Authorization::clearResolvedInstance('authorization');

        self::actAsTheGatesUser($container, $subject);
    }

    /**
     * Bind, in place of Laravel's Gate, one whose user is the subject's
     * identity, or its principal when it has none, so the Gate's checks are
     * about the subject rather than a guest's. The Gate keeps every ability,
     * policy and callback registered so far, the package's hook among them, and
     * lives in the test's container, so it goes with the container when the
     * test ends.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return void
     */
    private static function actAsTheGatesUser(Container $container, Subject $subject): void
    {
        $container->instance(GateContract::class, $container->make(GateContract::class)->forUser($subject->identity ?? $subject->subject));

        // Clear the facade's resolved-instance cache so the next static call
        // reaches the Gate just bound.
        Gate::clearResolvedInstance(GateContract::class);
    }

    /**
     * Resolve the Laravel container to bind the test's subject resolver into.
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
    private function resolveTestingContainer(): Container
    {
        /** @var array<string, mixed> $vars */
        $vars = \get_object_vars($this);
        $app  = $vars['app'] ?? null;

        if ($app instanceof Container) {
            return $app;
        }

        return Container::getInstance();
    }

    /**
     * Describe the resource a check named, for an assertion's message: its
     * identifier, or nothing for no resource or one that cannot be identified.
     *
     * @param  mixed  $resource
     * @return string
     */
    private static function describeResource(mixed $resource): string
    {
        $reference = ResourceReferences::of($resource);

        return $reference instanceof ResourceReference ? " on resource '{$reference->identifier}'" : '';
    }
}
