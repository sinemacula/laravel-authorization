<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Support\BladeHelpers;
use Tests\Feature\Stubs\RolesOnlyPrincipal;
use Tests\TestCase;

/**
 * Coverage for the narrow-contract mismatch branches of the
 * shipped Blade helpers. A principal that implements
 * `SupportsRoles` but not `SupportsPermissions` must still resolve
 * role directives successfully, while every permission-scoped
 * directive falls back to a safe `false` — keeping the view layer
 * fail-closed when consumers compose narrow contracts per-role.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BladeHelpers::class)]
final class BladeHelpersNarrowContractsTest extends TestCase
{
    /**
     * Swap in a resolver that returns a `RolesOnlyPrincipal` before
     * every test.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $principal = new RolesOnlyPrincipal;

        $resolver = new class ($principal) implements PrincipalResolver {
            /**
             * Create a new resolver wrapping a fixed principal.
             *
             * @param  \Tests\Feature\Stubs\RolesOnlyPrincipal  $principal
             * @return void
             */
            public function __construct(

                /** The principal returned by every resolution call. */
                private readonly RolesOnlyPrincipal $principal,

            ) {}

            /**
             * Resolve the current principal.
             *
             * @return object|null
             *
             * @phpstan-ignore-next-line return.unusedType (test stub always returns non-null)
             */
            #[\Override]
            public function resolve(): ?object
            {
                return $this->principal;
            }
        };

        $this->app->instance(PrincipalResolver::class, $resolver); // @phpstan-ignore method.nonObject (test container is non-null)
        $this->app->forgetInstance('authorization'); // @phpstan-ignore method.nonObject (test container is non-null)
        $this->app->forgetInstance(\SineMacula\Laravel\Authorization\AuthorizationManager::class); // @phpstan-ignore method.nonObject (test container is non-null)
    }

    /**
     * A principal that supports only roles still resolves
     * `hasAllRoles` honestly.
     *
     * @return void
     */
    public function testHasAllRolesOnRolesOnlyPrincipalResolvesByRoleOnly(): void
    {
        self::assertTrue(BladeHelpers::hasAllRoles(['editor']));
        self::assertFalse(BladeHelpers::hasAllRoles(['editor', 'admin']));
    }

    /**
     * A principal that does not implement `SupportsPermissions`
     * yields `false` from the any-permission helper — the narrow
     * contract mismatch branch.
     *
     * @return void
     */
    public function testHasPermissionFallsBackWhenContractMissing(): void
    {
        self::assertFalse(BladeHelpers::hasPermission(['posts:create']));
    }

    /**
     * A principal that does not implement `SupportsPermissions`
     * yields `false` from the all-permissions helper.
     *
     * @return void
     */
    public function testHasAllPermissionsFallsBackWhenContractMissing(): void
    {
        self::assertFalse(BladeHelpers::hasAllPermissions(['posts:create']));
    }
}
