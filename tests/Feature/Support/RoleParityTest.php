<?php

declare(strict_types = 1);

namespace Tests\Feature\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\GranteeGuardMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\ParentGuardMismatchException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\RoleParity;
use Tests\TestCase;

/**
 * Feature tests for owner and guard parity between a role and its permissions,
 * its parent and its grantees.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RoleParity::class)]
final class RoleParityTest extends TestCase
{
    /** @var array{tenant_type: string, tenant_id: string} One tenant's owner columns. */
    private const array TENANT_A = ['tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a'];

    /** @var array{tenant_type: string, tenant_id: string} Another tenant's owner columns. */
    private const array TENANT_B = ['tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-b'];

    /**
     * A role carries the platform's permissions and its own tenant's, with a
     * compatible guard.
     *
     * @return void
     */
    public function testARoleCarriesThePlatformsAndItsOwnTenantsPermissions(): void
    {
        $platformRole = self::role('editor', 'web');
        $tenantRole   = self::role('author', 'web', self::TENANT_A);

        RoleParity::assertCarries($platformRole, self::permission('posts:read', 'web'));
        RoleParity::assertCarries($platformRole, self::permission('posts:edit'));
        RoleParity::assertCarries($tenantRole, self::permission('posts:list', 'web'));
        RoleParity::assertCarries($tenantRole, self::permission('posts:own', null, self::TENANT_A));
        RoleParity::assertCarries(self::role('agnostic'), self::permission('posts:api', 'api'));

        $this->expectNotToPerformAssertions();
    }

    /**
     * A role cannot carry a permission of another guard, nor one another tenant
     * owns, nor, as a platform role, a tenant's.
     *
     * @return void
     */
    public function testARoleCannotCarryAMismatchedPermission(): void
    {
        $refusals = [
            [self::role('editor', 'web'), self::permission('posts:read', 'api'), GuardMismatchException::class],
            [self::role('author', null, self::TENANT_A), self::permission('posts:own', null, self::TENANT_B), OwnerMismatchException::class],
            [self::role('viewer'), self::permission('posts:mine', null, self::TENANT_A), OwnerMismatchException::class],
        ];

        foreach ($refusals as [$role, $permission, $exception]) {
            try {
                RoleParity::assertCarries($role, $permission);
                self::fail("{$permission->name} was carried by {$role->name}.");
            } catch (GuardMismatchException|OwnerMismatchException $refused) {
                self::assertInstanceOf($exception, $refused);
            }
        }
    }

    /**
     * A role sits under the platform's roles and its own tenant's of a
     * compatible guard, and under no other.
     *
     * @return void
     */
    public function testARoleSitsOnlyUnderAMatchingParent(): void
    {
        RoleParity::assertUnder(self::role('child', 'web', self::TENANT_A), self::role('parent', 'web'));
        RoleParity::assertUnder(self::role('child-2', null, self::TENANT_A), self::role('parent-2', 'api', self::TENANT_A));

        try {
            RoleParity::assertUnder(self::role('child-3', 'web'), self::role('parent-3', 'api'));
            self::fail('A parent of another guard was accepted.');
        } catch (ParentGuardMismatchException $exception) {
            self::assertSame('parent-3', $exception->getParentName());
        }

        try {
            RoleParity::assertUnder(self::role('child-4'), self::role('parent-4', null, self::TENANT_A));
            self::fail('A tenant parent of a platform role was accepted.');
        } catch (OwnerMismatchException $exception) {
            self::assertSame('parent role', $exception->getRelatedKind());
            self::assertNull($exception->getRoleOwner());
        }
    }

    /**
     * A role or permission is grantable to a grantee of its guard, to one that
     * declares none, and, without a guard, to any; not to another guard's.
     *
     * @return void
     */
    public function testAGrantMustSuitTheGranteesGuard(): void
    {
        RoleParity::assertGrantable('role', self::role('editor', 'web'), 'web');
        RoleParity::assertGrantable('role', self::role('author', 'web'), null);
        RoleParity::assertGrantable('permission', self::permission('posts:read'), 'api');

        $this->expectExceptionObject(new GranteeGuardMismatchException('role', 'viewer', 'web', 'api'));

        RoleParity::assertGrantable('role', self::role('viewer', 'web'), 'api');
    }

    /**
     * Create a role.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @param  array<string, string>  $owner
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function role(string $name, ?string $guard = null, array $owner = []): Role
    {
        return new Role(['name' => $name, 'guard' => $guard, ...$owner]);
    }

    /**
     * Create a permission.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @param  array<string, string>  $owner
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private static function permission(string $name, ?string $guard = null, array $owner = []): Permission
    {
        return new Permission(['name' => $name, 'guard' => $guard, ...$owner]);
    }
}
