<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Pivots\RolePermission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\ChecksTheConnectionName;
use Tests\Feature\Stubs\CustomPermission;
use Tests\Feature\Stubs\CustomRole;
use Tests\TestCase;

/**
 * Feature tests for the `RolePermission` pivot built from either side of the
 * role-permission relation.
 *
 * `Role::permissions()` builds the pivot with the role column as its foreign
 * key; `Permission::roles()` builds it with the permission column as its
 * foreign key. Guard parity must read the right column on each side.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RolePermission::class)]
#[CoversClass(GuardMismatchException::class)]
final class RolePermissionTest extends TestCase
{
    use CatchesRefusals, ChecksTheConnectionName;

    /** @var string The guard-mismatch message for the `editor` role and `posts:edit` permission. */
    private const string MISMATCH = 'Guard mismatch: role \'editor\' (guard \'web\') cannot carry permission \'posts:edit\' (guard \'api\').'
        . ' Scope one side to null for a guard-agnostic attachment, or match the guards.';

    /**
     * The expiry is written in UTC whatever zone it is given in, and read back
     * as a UTC instant.
     *
     * @return void
     */
    public function testTheExpiryIsStoredAndReadInUtc(): void
    {
        $role       = Role::query()->create(['name' => 'editor']);
        $permission = Permission::query()->create(['name' => 'posts:edit']);

        $role->permissions()->attach($permission->id, ['expires_at' => Carbon::parse('2099-01-01 13:00:00', 'Europe/Paris')]);

        $pivot = $role->permissions()->sole()->getRelation('pivot');

        self::assertSame('2099-01-01 12:00:00', DB::table('role_permissions')->value('expires_at'));
        self::assertInstanceOf(RolePermission::class, $pivot);
        self::assertSame('2099-01-01 12:00:00 UTC', $pivot->expires_at?->format('Y-m-d H:i:s e'));
    }

    /**
     * A role cannot carry a permission another tenant owns, nor, as a platform
     * role, a tenant's; a tenant's role carries its own.
     *
     * @return void
     */
    public function testARoleCarriesOnlyThePlatformsAndItsOwnTenantsPermissions(): void
    {
        $owned  = Permission::query()->create(['name' => 'tenant:read', 'tenant_type' => 'tenant', 'tenant_id' => 't-1']);
        $mine   = Role::query()->create(['name' => 'mine', 'tenant_type' => 'tenant', 'tenant_id' => 't-1']);
        $theirs = Role::query()->create(['name' => 'theirs', 'tenant_type' => 'tenant', 'tenant_id' => 't-2']);

        $mine->permissions()->attach($owned->id);

        foreach ([$theirs, Role::query()->create(['name' => 'platform'])] as $role) {
            $refusal = self::refusalOf(static fn () => $role->permissions()->attach($owned->id));

            self::assertInstanceOf(OwnerMismatchException::class, $refusal);
            self::assertSame('permission', $refusal->getRelatedKind());
        }

        self::assertSame(1, DB::table('role_permissions')->count());
    }

    /**
     * Attaching from the permission side with matching guards writes one pivot
     * row with each id in its own column.
     *
     * @return void
     */
    public function testAttachFromPermissionSideWithMatchingGuardsPersists(): void
    {
        $role       = $this->makeRole('web');
        $permission = $this->makePermission('web');

        $permission->roles()->attach($role->id);

        self::assertSame(
            [['role_id' => $role->id, 'permission_id' => $permission->id]],
            $this->pivotRows(),
        );
    }

    /**
     * Attaching from the permission side with two concrete, different guards is
     * refused with the role and permission on their own sides of the message.
     *
     * @return void
     */
    public function testAttachFromPermissionSideWithMismatchedGuardsThrows(): void
    {
        $role       = $this->makeRole('web');
        $permission = $this->makePermission('api');

        $this->assertGuardMismatchWritesNothing(static fn () => $permission->roles()->attach($role->id));
    }

    /**
     * Syncing from the permission side runs the same guard parity check.
     *
     * @return void
     */
    public function testSyncFromPermissionSideWithMismatchedGuardsThrows(): void
    {
        $role       = $this->makeRole('web');
        $permission = $this->makePermission('api');

        $this->assertGuardMismatchWritesNothing(static fn () => $permission->roles()->sync([$role->id]));
    }

    /**
     * Attaching from the role side keeps reading the role column as the foreign
     * key.
     *
     * @return void
     */
    public function testAttachFromRoleSideWithMismatchedGuardsThrows(): void
    {
        $role       = $this->makeRole('web');
        $permission = $this->makePermission('api');

        $this->assertGuardMismatchWritesNothing(static fn () => $role->permissions()->attach($permission->id));
    }

    /**
     * Attaching from the role side with matching guards writes one pivot row
     * with each id in its own column.
     *
     * @return void
     */
    public function testAttachFromRoleSideWithMatchingGuardsPersists(): void
    {
        $role       = $this->makeRole('web');
        $permission = $this->makePermission('web');

        $role->permissions()->attach($permission->id);

        self::assertSame(
            [['role_id' => $role->id, 'permission_id' => $permission->id]],
            $this->pivotRows(),
        );
    }

    /**
     * From the permission side the in-memory permission is the parent, so its
     * unsaved guard is the one checked rather than the stored one.
     *
     * @return void
     */
    public function testPermissionSideUsesInMemoryPermissionAsParent(): void
    {
        $role       = $this->makeRole('web');
        $permission = $this->makePermission('web');

        $permission->guard = 'api';

        $this->assertGuardMismatchWritesNothing(static fn () => $permission->roles()->attach($role->id));
    }

    /**
     * The permission side is recognised through the configured permission
     * subclass.
     *
     * @return void
     */
    public function testPermissionSideIsRecognisedForConfiguredPermissionClass(): void
    {
        $this->configurePermissionSubclass();

        $role       = $this->makeRole('web');
        $permission = CustomPermission::query()->create(['name' => 'posts:edit', 'guard' => 'api']);

        $this->assertGuardMismatchWritesNothing(static fn () => $permission->roles()->attach($role->id));
    }

    /**
     * A shipped `Permission` instance is still recognised as the permission
     * side when a subclass is configured, so matching guards persist the row
     * with each id in its own column.
     *
     * @return void
     */
    public function testPermissionSideIsRecognisedForBasePermissionWithConfiguredSubclass(): void
    {
        $this->configurePermissionSubclass();

        $role       = $this->makeRole('web');
        $permission = $this->makePermission('web');

        $permission->roles()->attach($role->id);

        self::assertSame(
            [['role_id' => $role->id, 'permission_id' => $permission->id]],
            $this->pivotRows(),
        );
    }

    /**
     * A shipped `Permission` instance with a configured subclass is checked for
     * guard parity from the permission side.
     *
     * @return void
     */
    public function testBasePermissionWithConfiguredSubclassAndMismatchedGuardsThrows(): void
    {
        $this->configurePermissionSubclass();

        $role       = $this->makeRole('web');
        $permission = $this->makePermission('api');

        $this->assertGuardMismatchWritesNothing(static fn () => $permission->roles()->attach($role->id));
    }

    /**
     * A shipped `Permission` instance is still used as the in-memory parent
     * when a subclass is configured, so its unsaved guard is the one checked.
     *
     * @return void
     */
    public function testBasePermissionWithConfiguredSubclassIsUsedAsInMemoryParent(): void
    {
        $this->configurePermissionSubclass();

        $role       = $this->makeRole('web');
        $permission = $this->makePermission('web');

        $permission->guard = 'api';

        $this->assertGuardMismatchWritesNothing(static fn () => $permission->roles()->attach($role->id));
    }

    /**
     * A shipped `Role` instance is still used as the in-memory parent when a
     * subclass is configured, so its unsaved guard is the one checked.
     *
     * @return void
     */
    public function testBaseRoleWithConfiguredSubclassIsUsedAsInMemoryParent(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.models.role', CustomRole::class);

        $role       = $this->makeRole('api');
        $permission = $this->makePermission('api');

        $role->guard = 'web';

        $this->assertGuardMismatchWritesNothing(static fn () => $role->permissions()->attach($permission->id));
    }

    /**
     * A role parent whose id is not the row's role id is not the in-memory
     * role, so the stored role's guard is the one checked.
     *
     * @return void
     */
    public function testRoleParentWithDifferentIdIsNotUsedAsInMemoryRole(): void
    {
        $role       = $this->makeRole('web');
        $permission = $this->makePermission('web');
        $parent     = Role::query()->create(['name' => 'author', 'guard' => 'api']);

        $this->savePivot($parent, $role->id, $permission->id);

        self::assertSame(
            [['role_id' => $role->id, 'permission_id' => $permission->id]],
            $this->pivotRows(),
        );
    }

    /**
     * A parent that is not a role is not the in-memory role, even when its id
     * is the row's role id.
     *
     * @return void
     */
    public function testNonRoleParentWithRoleIdIsNotUsedAsInMemoryRole(): void
    {
        $role       = $this->makeRole('web');
        $permission = $this->makePermission('web');
        $parent     = new Permission(['name' => 'posts:delete', 'guard' => 'api']);
        $parent->id = $role->id;

        $this->savePivot($parent, $role->id, $permission->id);

        self::assertSame(
            [['role_id' => $role->id, 'permission_id' => $permission->id]],
            $this->pivotRows(),
        );
    }

    /**
     * A permission parent whose id is not the row's permission id is not the
     * in-memory permission, so the stored permission's guard is the one
     * checked.
     *
     * @return void
     */
    public function testPermissionParentWithDifferentIdIsNotUsedAsInMemoryPermission(): void
    {
        $role       = $this->makeRole('web');
        $permission = $this->makePermission('web');
        $parent     = Permission::query()->create(['name' => 'posts:delete', 'guard' => 'api']);

        $this->savePivot($parent, $role->id, $permission->id);

        self::assertSame(
            [['role_id' => $role->id, 'permission_id' => $permission->id]],
            $this->pivotRows(),
        );
    }

    /**
     * A tenant-owned role is found as the stored parent when no tenant is
     * resolved, which hides it from ordinary queries: whether the parent exists
     * does not depend on the request's tenant.
     *
     * @return void
     */
    public function testTenantOwnedRoleIsFoundAsStoredParentWithoutTenant(): void
    {
        $role       = Role::query()->create(['name' => 'tenant-editor', 'guard' => 'web', 'tenant_type' => 'tenant', 'tenant_id' => 't-1']);
        $permission = $this->makePermission('web');
        $parent     = Permission::query()->create(['name' => 'posts:delete', 'guard' => 'web']);

        self::assertNull(Role::query()->find($role->id));

        $this->savePivot($parent, $role->id, $permission->id);

        self::assertSame(
            [['role_id' => $role->id, 'permission_id' => $permission->id]],
            $this->pivotRows(),
        );
    }

    /**
     * A tenant-owned permission is found as the stored parent when no tenant is
     * resolved, as for the role side.
     *
     * @return void
     */
    public function testTenantOwnedPermissionIsFoundAsStoredParentWithoutTenant(): void
    {
        $role       = Role::query()->create(['name' => 'editor', 'guard' => 'web', 'tenant_type' => 'tenant', 'tenant_id' => 't-1']);
        $permission = Permission::query()->create(['name' => 'tenant:read', 'guard' => 'web', 'tenant_type' => 'tenant', 'tenant_id' => 't-1']);
        $parent     = Role::query()->create(['name' => 'author', 'guard' => 'web']);

        self::assertNull(Permission::query()->find($permission->id));

        $this->savePivot($parent, $role->id, $permission->id);

        self::assertSame(
            [['role_id' => $role->id, 'permission_id' => $permission->id]],
            $this->pivotRows(),
        );
    }

    /**
     * A parent that is not a permission is not the in-memory permission, even
     * when its id is the row's permission id.
     *
     * @return void
     */
    public function testNonPermissionParentWithPermissionIdIsNotUsedAsInMemoryPermission(): void
    {
        $role       = $this->makeRole('web');
        $permission = $this->makePermission('web');
        $parent     = new Role(['name' => 'author', 'guard' => 'api']);
        $parent->id = $permission->id;

        $this->savePivot($parent, $role->id, $permission->id);

        self::assertSame(
            [['role_id' => $role->id, 'permission_id' => $permission->id]],
            $this->pivotRows(),
        );
    }

    /**
     * A pivot built outside a relation reads the table's fixed `role_id` and
     * `permission_id` columns, so guard parity still holds.
     *
     * @return void
     */
    public function testPivotWithoutARelationReadsTheFixedColumns(): void
    {
        $pivot = new RolePermission;
        $pivot->setTable('role_permissions');
        $pivot->setRawAttributes(['role_id' => $this->makeRole('web')->id, 'permission_id' => $this->makePermission('api')->id]);

        $this->expectException(GuardMismatchException::class);

        $pivot->save();
    }

    /**
     * Keys a relation supplies win over the fixed columns on the role side,
     * where the foreign key is the role column.
     *
     * @return void
     */
    public function testRelationSuppliedKeysAreReadOnTheRoleSide(): void
    {
        $role       = $this->makeRole('web');
        $permission = $this->makePermission('api');

        $pivot = new RolePermission;
        $pivot->setTable('role_permissions');
        $pivot->setPivotKeys('role_ref', 'permission_ref');
        $pivot->setRawAttributes(['role_ref' => $role->id, 'permission_ref' => $permission->id]);

        $this->expectException(GuardMismatchException::class);
        $this->expectExceptionMessage(self::MISMATCH);

        $pivot->save();
    }

    /**
     * Keys a relation supplies win over the fixed columns on the permission
     * side, where the foreign key is the permission column.
     *
     * @return void
     */
    public function testRelationSuppliedKeysAreReadOnThePermissionSide(): void
    {
        $role       = $this->makeRole('web');
        $permission = $this->makePermission('api');

        $pivot              = new RolePermission;
        $pivot->pivotParent = $permission;
        $pivot->setTable('role_permissions');
        $pivot->setPivotKeys('permission_ref', 'role_ref');
        $pivot->setRawAttributes(['role_ref' => $role->id, 'permission_ref' => $permission->id]);

        $this->expectException(GuardMismatchException::class);
        $this->expectExceptionMessage(self::MISMATCH);

        $pivot->save();
    }

    /**
     * Create the pivot whose connection is checked.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    #[\Override]
    protected static function newConnectionModel(): Model
    {
        return new RolePermission;
    }

    /**
     * Determine whether the class under test is a pivot.
     *
     * @return bool
     */
    #[\Override]
    protected static function isAPivot(): bool
    {
        return true;
    }

    /**
     * Save a pivot row built directly against the given parent, outside any
     * relation, so the parent and the row's ids can disagree.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $parent
     * @param  string  $roleId
     * @param  string  $permissionId
     * @return void
     */
    private function savePivot(Model $parent, string $roleId, string $permissionId): void
    {
        RolePermission::fromAttributes($parent, ['role_id' => $roleId, 'permission_id' => $permissionId], 'role_permissions')->save();
    }

    /**
     * Point `authorization.models.permission` at the subclass stub.
     *
     * @return void
     */
    private function configurePermissionSubclass(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.models.permission', CustomPermission::class);
    }

    /**
     * Assert the callback is refused for guard mismatch and writes no pivot
     * row.
     *
     * @param  callable(): mixed  $callback
     * @return void
     */
    private function assertGuardMismatchWritesNothing(callable $callback): void
    {
        try {
            $callback();
            self::fail('GuardMismatchException was not thrown.');
        } catch (GuardMismatchException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame(self::MISMATCH, $exception->getMessage());
            self::assertSame([], $this->pivotRows());
        }
    }

    /**
     * Return every pivot row as a column map.
     *
     * @return list<array<string, mixed>>
     */
    private function pivotRows(): array
    {
        /** @var list<array<string, mixed>> */
        return DB::table('role_permissions')
            ->get(['role_id', 'permission_id'])
            ->map(static fn (object $row): array => (array) $row)
            ->all();
    }

    /**
     * Create the `editor` role under the given guard.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private function makeRole(string $guard): Role
    {
        return Role::query()->create(['name' => 'editor', 'guard' => $guard]);
    }

    /**
     * Create the `posts:edit` permission under the given guard.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private function makePermission(string $guard): Permission
    {
        return Permission::query()->create(['name' => 'posts:edit', 'guard' => $guard]);
    }
}
