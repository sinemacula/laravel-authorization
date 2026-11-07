<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Events\Permission\Created as PermissionCreated;
use SineMacula\Laravel\Authorization\Events\Permission\Deleted as PermissionDeleted;
use SineMacula\Laravel\Authorization\Events\Permission\Updated as PermissionUpdated;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationNameException;
use SineMacula\Laravel\Authorization\Exceptions\SystemPermissionProtectedException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Exceptions\UnsavedRecordException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\PermissionService;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ComparesReferences;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Feature\Stubs\CustomPermission;
use Tests\TestCase;

/**
 * Feature tests for `PermissionService`, which creates, renames, describes,
 * deletes and lists permissions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PermissionService::class)]
final class PermissionServiceTest extends TestCase
{
    use ComparesReferences, UsesAnAuthorizationConnection;

    /**
     * A name finds the permission the lookup ranks first under the guard, and
     * an unknown name is refused.
     *
     * @return void
     */
    public function testFindsAPermissionByName(): void
    {
        $agnostic = Permission::query()->create(['name' => 'posts:edit']);
        $web      = Permission::query()->create(['name' => 'posts:edit', 'guard' => 'web']);

        self::assertSame($web->id, self::service()->find('posts:edit', 'web')->id);
        self::assertSame($agnostic->id, self::service()->find('posts:edit', 'api')->id);

        $this->expectException(UnknownPermissionException::class);

        self::service()->find('ghost');
    }

    /**
     * The service is bound once in the container.
     *
     * @return void
     */
    public function testIsBoundAsASingleton(): void
    {
        self::assertSame(self::service(), self::service());
    }

    /**
     * A permission is created with its attributes, through the configured
     * class, and reported by the observer.
     *
     * @return void
     */
    public function testCreatesAPermission(): void
    {
        $this->config()->set('authorization.models.permission', CustomPermission::class);

        Event::fake([PermissionCreated::class]);

        $permission = self::service()->create('posts.edit', 'web', 'Edit posts', 'Posts');

        self::assertInstanceOf(CustomPermission::class, $permission);
        self::assertTrue(Str::isUuid($permission->id));
        self::assertSame(
            ['name' => 'posts.edit', 'guard' => 'web', 'description' => 'Edit posts', 'category' => 'Posts'],
            Permission::query()->whereKey($permission->id)->sole()->only(['name', 'guard', 'description', 'category']),
        );
        Event::assertDispatched(PermissionCreated::class);
    }

    /**
     * A permission created with an id keeps it.
     *
     * @return void
     */
    public function testCreatesAPermissionWithTheGivenId(): void
    {
        $id = (string) Str::uuid();

        self::assertSame($id, self::service()->create('posts:edit', id: $id)->id);
    }

    /**
     * A name the name rule refuses is not written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAnInvalidName(): void
    {
        try {
            self::service()->create('posts edit');
            self::fail('The name was not refused.');
        } catch (InvalidAuthorizationNameException) {
            self::assertSame(0, Permission::query()->count());
        }
    }

    /**
     * A permission is written on the package's connection.
     *
     * @return void
     */
    public function testCreatesThePermissionOnThePackageConnection(): void
    {
        $this->useAnAuthorizationConnection();

        self::service()->create('posts:edit');

        self::assertSame(1, self::authorizationConnection()->table('permissions')->count());
        self::assertSame(0, DB::table('permissions')->count());
    }

    /**
     * A permission is renamed and described by model or by name.
     *
     * @return void
     */
    public function testRenamesAndDescribesAPermission(): void
    {
        $permission = Permission::query()->create(['name' => 'posts:edit']);

        self::assertSame('posts:update', self::service()->rename('posts:edit', 'posts:update')->name);
        self::assertSame('Update posts', self::service()->describe($permission, 'Update posts')->description);
        self::assertNull(self::service()->describe('posts:update', null)->description);
        self::assertSame(['posts:update', null], [$permission->fresh()?->name, $permission->fresh()?->description]);
    }

    /**
     * A system permission keeps its protection through the service.
     *
     * @return void
     */
    public function testASystemPermissionCannotBeDeleted(): void
    {
        Permission::query()->create(['name' => 'admin:*', 'is_system' => true]);

        $this->expectException(SystemPermissionProtectedException::class);

        self::service()->delete('admin:*');
    }

    /**
     * A permission is deleted by model or by name; an unknown name throws.
     *
     * @return void
     */
    public function testDeletesAPermission(): void
    {
        $permission = Permission::query()->create(['name' => 'posts:edit']);

        Permission::query()->create(['name' => 'posts:delete']);

        self::service()->delete($permission);
        self::service()->delete('posts:delete');

        self::assertSame(0, Permission::query()->count());

        $this->expectExceptionObject(new UnknownPermissionException('ghost'));

        self::service()->delete('ghost');
    }

    /**
     * An unsaved permission is refused by every change, so none creates a
     * permission outside `create()`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChangesRefuseAnUnsavedPermission(): void
    {
        $calls = [
            'rename'   => static fn (PermissionService $service, Permission $permission): mixed => $service->rename($permission, 'posts:update'),
            'describe' => static fn (PermissionService $service, Permission $permission): mixed => $service->describe($permission, 'Edits'),
            'delete'   => static function (PermissionService $service, Permission $permission): void {
                $service->delete($permission);
            },
        ];

        foreach ($calls as $name => $call) {
            try {
                $call(self::service(), new Permission(['name' => 'posts:edit']));
                self::fail("The {$name} did not refuse the unsaved permission.");
            } catch (UnsavedRecordException $exception) {
                self::assertSame('permission', $exception->getKind());
            }
        }

        self::assertSame(0, Permission::query()->count());
    }

    /**
     * The permissions are listed by name; with a guard, those of that guard or
     * guard-agnostic.
     *
     * @return void
     */
    public function testListsThePermissions(): void
    {
        Permission::query()->create(['name' => 'posts:view', 'guard' => 'api']);
        Permission::query()->create(['name' => 'posts:edit', 'guard' => 'web']);
        Permission::query()->create(['name' => 'posts:audit']);

        self::assertSame(['posts:audit', 'posts:edit', 'posts:view'], self::service()->list()->pluck('name')->all());
        self::assertSame(['posts:audit', 'posts:view'], self::service()->list('api')->pluck('name')->all());
    }

    /**
     * A change made through the service carries the trusted operation, with no
     * actor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeCarriesTheActor(): void
    {

        self::service()->create('posts:edit');

        Event::fake([PermissionUpdated::class]);

        self::service()->rename('posts:edit', 'posts:write');

        Event::assertDispatched(PermissionUpdated::class, static fn (PermissionUpdated $event): bool => $event->operation->actor === null
            && $event->name                                                                                                      === 'posts:write');
    }

    /**
     * Deleting a permission through the service reports, as trusted work, every
     * grantee that held it and every role that carried it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletingAPermissionReportsWhoLostIt(): void
    {
        $permission = self::service()->create('posts:edit');
        $role       = Role::query()->create(['name' => 'editor']);

        $role->permissions()->attach($permission->id);
        app(GrantService::class)->grantPermission(new Reference('user', '1'), $permission);

        Event::fake([PermissionDeleted::class]);

        self::service()->delete($permission);

        Event::assertDispatchedTimes(PermissionDeleted::class, 1);
        Event::assertDispatched(PermissionDeleted::class, static fn (PermissionDeleted $event): bool => $event->operation->actor === null
            && self::keysOf($event->grantees)                                                                                    === ['user:1']
            && self::keysOf($event->roles)                                                                                       === self::keysOf([Reference::of($role)]));
    }

    /**
     * Return the permission service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\PermissionService
     */
    private static function service(): PermissionService
    {
        return app(PermissionService::class);
    }

    /**
     * Return the configuration repository.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): ConfigRepository
    {
        /** @var \Illuminate\Config\Repository */
        return $this->app?->make(ConfigRepository::class);
    }
}
