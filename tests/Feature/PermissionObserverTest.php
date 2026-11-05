<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Events\Permission\Created as PermissionCreated;
use SineMacula\Laravel\Authorization\Events\Permission\Deleted as PermissionDeleted;
use SineMacula\Laravel\Authorization\Events\Permission\Updated as PermissionUpdated;
use SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\OwnerChangedException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\PermissionObserver;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\PermissionService;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\ComparesReferences;
use Tests\TestCase;

/**
 * Feature tests for the events the permission observer builds: what each
 * carries, and the grantees and roles a delete reports.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PermissionObserver::class)]
final class PermissionObserverTest extends TestCase
{
    use CatchesRefusals, ComparesReferences;

    /**
     * Changing a permission's guard re-checks every role that carries it, and a
     * saved permission keeps its owner.
     *
     * @return void
     */
    public function testAGuardChangeIsCheckedAgainstItsRoles(): void
    {
        $permission = Permission::query()->create(['name' => 'posts:read']);

        Role::query()->create(['name' => 'editor', 'guard' => 'web'])->permissions()->attach($permission->id);

        $permission->guard = 'web';
        $permission->save();

        $permission->guard = 'api';

        $refusal = self::refusalOf(static fn (): bool => $permission->save());

        self::assertInstanceOf(GuardMismatchException::class, $refusal);
        self::assertSame('editor', $refusal->getRoleName());

        $permission->guard = 'web';
        $permission->forceFill(['tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a']);

        $this->expectException(OwnerChangedException::class);

        $permission->save();
    }

    /**
     * Creating a permission reports it as a snapshot: its reference, name,
     * guard, tenant and system flag, for an operation with no actor.
     *
     * @return void
     */
    public function testReportsThePermissionCreated(): void
    {
        Event::fake([PermissionCreated::class]);

        $permission = Permission::query()->create(['name' => 'posts:edit', 'guard' => 'web', 'tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a']);
        $system     = Permission::query()->create(['name' => 'posts:purge', 'is_system' => true]);

        Event::assertDispatchedTimes(PermissionCreated::class, 2);
        Event::assertDispatched(PermissionCreated::class, static fn (PermissionCreated $event): bool => self::refersTo($event->permission, $permission)
            && $event->name  === 'posts:edit'
            && $event->guard === 'web'
            && self::refersTo($event->tenant, new Reference('stub_tenant', 'tenant-a'))
            && !$event->isSystem
            && $event->operation->actor === null);
        Event::assertDispatched(PermissionCreated::class, static fn (PermissionCreated $event): bool => self::refersTo($event->permission, $system)
            && $event->guard  === null
            && $event->tenant === null
            && $event->isSystem);
    }

    /**
     * Updating a permission reports the fields it changed, before and after.
     *
     * @return void
     */
    public function testReportsThePermissionUpdated(): void
    {
        $permission = Permission::query()->create(['name' => 'posts:edit', 'description' => 'Edit posts']);

        Event::fake([PermissionUpdated::class]);

        $permission->update(['name' => 'posts:write', 'description' => 'Write posts']);

        Event::assertDispatchedTimes(PermissionUpdated::class, 1);
        Event::assertDispatched(PermissionUpdated::class, static fn (PermissionUpdated $event): bool => self::refersTo($event->permission, $permission)
            && $event->name                                                                       === 'posts:write'
            && \array_intersect_key($event->changes['before'], ['name' => 1, 'description' => 1]) === ['name' => 'posts:edit', 'description' => 'Edit posts']
            && \array_intersect_key($event->changes['after'], ['name' => 1, 'description' => 1])  === ['name' => 'posts:write', 'description' => 'Write posts']);
    }

    /**
     * Deleting a permission reports, in one event, every grantee that held it
     * directly and every role that carried it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReportsThePermissionDeletedWithItsHoldersAndRoles(): void
    {
        $permission = Permission::query()->create(['name' => 'posts:edit']);
        $role       = Role::query()->create(['name' => 'editor']);

        $role->permissions()->attach($permission->id);

        app(GrantService::class)->grantPermission(new Reference('user', '2'), $permission);
        app(GrantService::class)->grantPermission(new Reference('user', '1'), $permission);

        Event::fake([PermissionDeleted::class]);

        $permission->delete();

        Event::assertDispatchedTimes(PermissionDeleted::class, 1);
        Event::assertDispatched(PermissionDeleted::class, static fn (PermissionDeleted $event): bool => self::refersTo($event->permission, $permission)
            && $event->name                   === 'posts:edit'
            && self::keysOf($event->grantees) === ['user:1', 'user:2']
            && self::keysOf($event->roles)    === self::keysOf([Reference::of($role)]));
    }

    /**
     * A permission written through the permission service reports the service
     * call's actor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReportsTheActorOfTheServiceCall(): void
    {
        Event::fake([PermissionCreated::class]);

        app(PermissionService::class)->create('posts:edit', actor: new Reference('user', 'admin-1'));

        Event::assertDispatched(PermissionCreated::class, static fn (PermissionCreated $event): bool => self::refersTo($event->operation->actor, new Reference('user', 'admin-1')));
    }
}
