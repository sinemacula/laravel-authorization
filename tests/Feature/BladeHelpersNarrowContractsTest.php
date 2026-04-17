<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
use SineMacula\Laravel\Authorization\Models\Role as RoleModel;
use SineMacula\Laravel\Authorization\Support\BladeHelpers;
use Tests\TestCase;

/**
 * Principal that satisfies `SupportsRoles` but not `SupportsPermissions`
 * — used to exercise the narrow-contract mismatch branches in
 * `BladeHelpers::hasAllRoles`, `hasPermission`, and `hasAllPermissions`.
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
final class RolesOnlyPrincipal implements SupportsRoles // phpcs:ignore PSR1.Classes.ClassDeclaration.MultipleClasses
{
    /**
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return static
     */
    public function assignRole(RoleModel|string $role): static
    {
        return $this;
    }

    /**
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return static
     */
    public function revokeRole(RoleModel|string $role): static
    {
        return $this;
    }

    /**
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Role|string>  $roles
     * @return static
     */
    public function syncRoles(array $roles): static
    {
        return $this;
    }

    /**
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return bool
     */
    public function hasRole(RoleModel|string $role): bool
    {
        return $role === 'editor';
    }

    /**
     * @return array<int, string>
     */
    public function getRoles(): array
    {
        return ['editor'];
    }
}

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
final class BladeHelpersNarrowContractsTest extends TestCase // phpcs:ignore PSR1.Classes.ClassDeclaration.MultipleClasses
{
    /**
     * Swap in a resolver that returns a `RolesOnlyPrincipal` before
     * every test.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $principal = new RolesOnlyPrincipal;

        $resolver = new class ($principal) implements PrincipalResolver {
            /**
             * @param  \Tests\Feature\RolesOnlyPrincipal  $principal
             */
            public function __construct(private readonly RolesOnlyPrincipal $principal) {}

            /**
             * @return object|null
             */
            public function resolve(): ?object // @phpstan-ignore return.unusedType
            {
                return $this->principal;
            }
        };

        $this->app->instance(PrincipalResolver::class, $resolver); // @phpstan-ignore method.nonObject
        $this->app->forgetInstance('authorization'); // @phpstan-ignore method.nonObject
        $this->app->forgetInstance(\SineMacula\Laravel\Authorization\AuthorizationManager::class); // @phpstan-ignore method.nonObject
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
