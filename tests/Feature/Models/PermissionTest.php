<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Pivots\RolePermission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\PermissionService;
use Tests\Feature\Stubs\CustomRole;

/**
 * Feature tests for the shipped `Permission` model: its string casts and the
 * `roles()` relation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Permission::class)]
final class PermissionTest extends StringCastsTestCase
{
    /**
     * The roles that carry the permission leave out a role whose grant has
     * expired, and carry each grant's expiry.
     *
     * @return void
     */
    public function testRolesLeaveOutAnExpiredGrant(): void
    {
        $permission = Permission::query()->create(['name' => 'posts:edit']);
        $live       = Role::query()->create(['name' => 'editor']);
        $lapsed     = Role::query()->create(['name' => 'author']);

        $live->permissions()->attach($permission->id, ['expires_at' => '2099-01-01 00:00:00']);
        $lapsed->permissions()->attach($permission->id, ['expires_at' => '2000-01-01 00:00:00']);

        $roles = $permission->roles()->get();
        $pivot = $roles->sole()->getRelation('pivot');

        self::assertSame(['editor'], $roles->pluck('name')->all());
        self::assertInstanceOf(RolePermission::class, $pivot);
        self::assertSame('2099-01-01 00:00:00', $pivot->expires_at?->format('Y-m-d H:i:s'));
    }

    /**
     * `roles()` returns the role class configured under
     * `authorization.models.role`.
     *
     * @return void
     */
    public function testRolesReturnsConfiguredRoleClass(): void
    {
        $this->useCustomRole();

        $role       = CustomRole::query()->create(['name' => 'editor', 'guard' => 'web']);
        $permission = Permission::query()->create(['name' => 'posts:edit', 'guard' => 'web']);

        $role->givePermission($permission);

        $roles = $permission->roles()->get();

        self::assertSame(CustomRole::class, $permission->roles()->getRelated()::class);
        self::assertCount(1, $roles);
        self::assertInstanceOf(CustomRole::class, $roles->first());
        self::assertSame($role->id, $roles->first()->id);
    }

    /**
     * `roles()` shares the table, columns and pivot model of
     * `Role::permissions()`.
     *
     * @return void
     */
    public function testRolesUsesTheRolePermissionPivot(): void
    {
        $relation = (new Permission)->roles();

        self::assertSame(RolePermission::class, $relation->getPivotClass());
        self::assertSame('role_permissions', $relation->getTable());
        self::assertSame('permission_id', $relation->getForeignPivotKeyName());
        self::assertSame('role_id', $relation->getRelatedPivotKeyName());
    }

    /**
     * Attaching a role from the permission side runs guard parity, so two
     * concrete, different guards are refused and nothing is written.
     *
     * @return void
     */
    public function testAttachingRoleWithMismatchedGuardIsRefused(): void
    {
        $this->useCustomRole();

        $role       = CustomRole::query()->create(['name' => 'editor', 'guard' => 'web']);
        $permission = Permission::query()->create(['name' => 'posts:edit', 'guard' => 'api']);

        try {
            $permission->roles()->attach($role->id);
            self::fail('GuardMismatchException was not thrown.');
        } catch (GuardMismatchException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame('Guard mismatch: role \'editor\' (guard \'web\') cannot carry permission \'posts:edit\' (guard \'api\').'
                . ' Scope one side to null for a guard-agnostic attachment, or match the guards.', $exception->getMessage());
            self::assertSame(0, DB::table('role_permissions')->count());
        }
    }

    /**
     * A name resolved without a guard is looked up under the configured default
     * guard.
     *
     * @return void
     */
    public function testResolvingANameWithoutAGuardUsesTheDefaultGuard(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.defaults.guard', 'api');

        Permission::query()->create(['name' => 'posts:edit', 'guard' => 'web']);
        $api = Permission::query()->create(['name' => 'posts:edit', 'guard' => 'api']);

        self::assertSame($api->id, app(PermissionService::class)->find('posts:edit')->id);
    }

    /**
     * Create an instance of the model under test.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    #[\Override]
    protected static function newModel(): Model
    {
        return new Permission;
    }

    /**
     * Return the model's fillable string columns.
     *
     * @return list<string>
     */
    #[\Override]
    protected static function stringColumns(): array
    {
        return ['name', 'guard', 'description', 'category', 'tenant_type', 'tenant_id'];
    }

    /**
     * Point `authorization.models.role` at the subclass stub.
     *
     * @return void
     */
    private function useCustomRole(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.models.role', CustomRole::class);
    }
}
