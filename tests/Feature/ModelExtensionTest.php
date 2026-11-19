<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabaseState;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\AfterClass;
use PHPUnit\Framework\Attributes\BeforeClass;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Exceptions\RoleHasChildrenException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Policy;
use Tests\Concerns\CatchesRefusals;
use Tests\Feature\Stubs\CustomPermission;
use Tests\Feature\Stubs\CustomRole;
use Tests\Feature\Stubs\StubGrantee;
use Tests\Fixtures\SoftDeletingRole;
use Tests\TestCase;

/**
 * Feature tests for role and permission subclasses registered in
 * `authorization.models`, as the model extension guide describes.
 *
 * The roles table carries a `deleted_at` column for this class alone, so the
 * schema is migrated afresh before its first test and after its last.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ModelClasses::class)]
final class ModelExtensionTest extends TestCase
{
    use CatchesRefusals;

    /**
     * Migrate afresh, so the first test adds the soft-delete column.
     *
     * @return void
     */
    #[BeforeClass]
    public static function migrateWithSoftDeletes(): void
    {
        RefreshDatabaseState::$migrated = false;
    }

    /**
     * Migrate afresh, so the next class runs without the soft-delete column.
     *
     * @return void
     */
    #[AfterClass]
    public static function migrateWithoutSoftDeletes(): void
    {
        RefreshDatabaseState::$migrated = false;
    }

    /**
     * A holder of a subclass role is allowed through the role's permissions and
     * through a policy attached under the subclass's morph class.
     *
     * @return void
     */
    public function testASubclassRoleDecidesACheck(): void
    {
        $this->useModels(CustomRole::class);

        $user = StubGrantee::query()->create(['id' => 'user-1']);
        $role = CustomRole::query()->create(['name' => 'editor']);

        $role->givePermission(CustomPermission::query()->create(['name' => 'posts:edit']));
        $role->attachPolicy(Policy::query()->create(['name' => 'publishers', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:publish']]]]]));
        $user->assignRole($role);

        self::assertSame([CustomRole::class], DB::table('authorizable_policies')->pluck('authorizable_type')->all());
        self::assertTrue(Authorization::for($user)->can('posts:edit'));
        self::assertTrue(Authorization::for($user)->can('posts:publish'));
        self::assertFalse(Authorization::for($user)->can('posts:delete'));
    }

    /**
     * A trashed role of a soft-deleting subclass no longer counts for its
     * holders, though their grants of it are kept for a restore.
     *
     * @return void
     */
    public function testATrashedRoleStopsGranting(): void
    {
        $this->useModels(SoftDeletingRole::class);

        $role = SoftDeletingRole::query()->create(['name' => 'editor']);

        $role->givePermission(CustomPermission::query()->create(['name' => 'posts:edit']));
        StubGrantee::query()->create(['id' => 'user-1'])->assignRole($role);

        self::assertTrue(Authorization::for(StubGrantee::query()->findOrFail('user-1'))->can('posts:edit'));

        $role->delete();

        $user = StubGrantee::query()->findOrFail('user-1');

        self::assertFalse($user->hasRole('editor'));
        self::assertSame([], $user->getRoles());
        self::assertSame([], $user->getPermissions());
        self::assertFalse(Authorization::for($user)->can('posts:edit'));
        self::assertSame(1, DB::table('authorizable_roles')->count());
    }

    /**
     * A parent passes its permissions and policies to the holders of its child
     * until it is trashed. A role with children cannot be trashed, and one set
     * as a parent once trashed passes nothing, as the hierarchy reads roles
     * through the subclass.
     *
     * @return void
     */
    public function testATrashedParentPassesNothingToItsChildren(): void
    {
        $this->useModels(SoftDeletingRole::class);

        $parent = SoftDeletingRole::query()->create(['name' => 'reader']);
        $child  = SoftDeletingRole::query()->create(['name' => 'writer', 'parent_id' => $parent->id]);

        $parent->givePermission(CustomPermission::query()->create(['name' => 'posts:read']));
        $parent->attachPolicy(Policy::query()->create(['name' => 'publishers', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:publish']]]]]));
        StubGrantee::query()->create(['id' => 'user-1'])->assignRole($child);

        $holder = StubGrantee::query()->findOrFail('user-1');

        self::assertTrue(Authorization::for($holder)->can('posts:read'));
        self::assertTrue(Authorization::for($holder)->can('posts:publish'));
        self::assertInstanceOf(RoleHasChildrenException::class, self::refusalOf($parent->delete(...)));

        $child->update(['parent_id' => null]);
        $parent->delete();
        $child->update(['parent_id' => $parent->id]);

        $user = StubGrantee::query()->findOrFail('user-1');

        self::assertSame(['writer'], $user->getRoles());
        self::assertSame([], $user->getPermissions());
        self::assertFalse(Authorization::for($user)->can('posts:read'));
        self::assertFalse(Authorization::for($user)->can('posts:publish'));
    }

    /**
     * With a shared store, a restored role grants its permissions again to its
     * holders and to the holders of a role set below it while it was trashed.
     *
     * @return void
     */
    public function testARestoredRoleGrantsAgainFromASharedStore(): void
    {
        $this->useSharedStore();

        $role  = SoftDeletingRole::query()->create(['name' => 'editor']);
        $child = SoftDeletingRole::query()->create(['name' => 'writer']);

        $role->givePermission(CustomPermission::query()->create(['name' => 'posts:edit']));
        StubGrantee::query()->create(['id' => 'user-1'])->assignRole($role);
        StubGrantee::query()->create(['id' => 'user-2'])->assignRole($child);

        $role->delete();
        $child->update(['parent_id' => $role->id]);

        $user = StubGrantee::query()->findOrFail('user-1');

        self::assertSame([], $user->getRoles());
        self::assertFalse(Authorization::for($user)->can('posts:edit'));
        self::assertFalse(Authorization::for(StubGrantee::query()->findOrFail('user-2'))->can('posts:edit'));

        $role->restore(); // @phpstan-ignore staticMethod.dynamicCall

        $user = StubGrantee::query()->findOrFail('user-1');

        self::assertSame(['editor'], $user->getRoles());
        self::assertTrue(Authorization::for($user)->can('posts:edit'));
        self::assertTrue(Authorization::for(StubGrantee::query()->findOrFail('user-2'))->can('posts:edit'));
    }

    /**
     * With a shared store, a policy attached to a trashed role counts for its
     * holders once the role is restored.
     *
     * @return void
     */
    public function testARestoredRolesPoliciesCountAgainFromASharedStore(): void
    {
        $this->useSharedStore();

        $role = SoftDeletingRole::query()->create(['name' => 'editor']);

        StubGrantee::query()->create(['id' => 'user-1'])->assignRole($role);

        $role->delete();
        $role->attachPolicy(Policy::query()->create(['name' => 'publishers', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:publish']]]]]));

        self::assertFalse(Authorization::for(StubGrantee::query()->findOrFail('user-1'))->can('posts:publish'));

        $role->restore(); // @phpstan-ignore staticMethod.dynamicCall

        self::assertTrue(Authorization::for(StubGrantee::query()->findOrFail('user-1'))->can('posts:publish'));
    }

    /**
     * Add the soft-delete column to the roles table once the package's schema
     * is migrated.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrationsAfterDatabaseRefreshed(): void
    {
        parent::defineDatabaseMigrationsAfterDatabaseRefreshed();

        Schema::table('roles', static function (Blueprint $table): void {
            $table->softDeletes();
        });
    }

    /**
     * Register the given role class, and the permission subclass, in
     * `authorization.models`.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Models\Role>  $role
     * @return void
     */
    private function useModels(string $role): void
    {
        config(['authorization.models.role' => $role, 'authorization.models.permission' => CustomPermission::class]);
    }

    /**
     * Register the soft-deleting role and keep entries in the array store.
     *
     * @return void
     */
    private function useSharedStore(): void
    {
        $this->useModels(SoftDeletingRole::class);

        config(['authorization.cache.store' => 'array']);

        $this->app?->forgetInstance(ResolutionCache::class);
    }
}
