<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Events\PermissionCreated;
use SineMacula\Laravel\Authorization\Events\PermissionDeleted;
use SineMacula\Laravel\Authorization\Events\PermissionUpdated;
use SineMacula\Laravel\Authorization\Events\PolicyCreated;
use SineMacula\Laravel\Authorization\Events\PolicyDeleted;
use SineMacula\Laravel\Authorization\Events\PolicyUpdated;
use SineMacula\Laravel\Authorization\Events\RoleCreated;
use SineMacula\Laravel\Authorization\Events\RoleDeleted;
use SineMacula\Laravel\Authorization\Events\RoleUpdated;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\TestCase;

/**
 * Feature coverage for the row-lifecycle events on `Role`,
 * `Permission`, and `Policy`.
 *
 * Each primitive ships a `Created` / `Updated` / `Deleted` trio.
 * The `Updated` variant carries the dirty attributes so audit
 * consumers can render a before/after diff without a second
 * round-trip.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Role::class)]
#[CoversClass(Permission::class)]
#[CoversClass(Policy::class)]
#[CoversClass(RoleCreated::class)]
#[CoversClass(RoleUpdated::class)]
#[CoversClass(RoleDeleted::class)]
#[CoversClass(PermissionCreated::class)]
#[CoversClass(PermissionUpdated::class)]
#[CoversClass(PermissionDeleted::class)]
#[CoversClass(PolicyCreated::class)]
#[CoversClass(PolicyUpdated::class)]
#[CoversClass(PolicyDeleted::class)]
final class LifecycleEventsTest extends TestCase
{
    /**
     * Creating a role dispatches `RoleCreated`.
     *
     * @return void
     */
    public function testRoleCreatedEventFires(): void
    {
        Event::fake([RoleCreated::class]);

        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'editor',
            'guard_name' => 'web',
        ]);

        Event::assertDispatched(
            RoleCreated::class,
            static fn (RoleCreated $event): bool => $event->role->is($role),
        );
    }

    /**
     * Updating a role dispatches `RoleUpdated` carrying the dirty
     * attribute set.
     *
     * @return void
     */
    public function testRoleUpdatedEventCarriesChanges(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'editor',
            'guard_name' => 'web',
        ]);

        Event::fake([RoleUpdated::class]);

        $role->description = 'Editor role';
        $role->save();

        Event::assertDispatched(
            RoleUpdated::class,
            static fn (RoleUpdated $event): bool => $event->role->is($role)
                && \array_key_exists('description', $event->changes)
                && $event->changes['description'] === 'Editor role',
        );
    }

    /**
     * Deleting a role dispatches `RoleDeleted`.
     *
     * @return void
     */
    public function testRoleDeletedEventFires(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'transient',
            'guard_name' => 'web',
        ]);

        Event::fake([RoleDeleted::class]);

        $role->delete();

        Event::assertDispatched(
            RoleDeleted::class,
            static fn (RoleDeleted $event): bool => (string) $event->role->getKey() === (string) $role->getKey(),
        );
    }

    /**
     * Creating a permission dispatches `PermissionCreated`.
     *
     * @return void
     */
    public function testPermissionCreatedEventFires(): void
    {
        Event::fake([PermissionCreated::class]);

        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'posts:create',
            'guard_name' => 'web',
        ]);

        Event::assertDispatched(
            PermissionCreated::class,
            static fn (PermissionCreated $event): bool => $event->permission->is($permission),
        );
    }

    /**
     * Updating a permission dispatches `PermissionUpdated` with
     * the change set.
     *
     * @return void
     */
    public function testPermissionUpdatedEventCarriesChanges(): void
    {
        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'posts:create',
            'guard_name' => 'web',
        ]);

        Event::fake([PermissionUpdated::class]);

        $permission->description = 'Create posts';
        $permission->save();

        Event::assertDispatched(
            PermissionUpdated::class,
            static fn (PermissionUpdated $event): bool => $event->permission->is($permission)
                && ($event->changes['description'] ?? null) === 'Create posts',
        );
    }

    /**
     * Deleting a permission dispatches `PermissionDeleted`.
     *
     * @return void
     */
    public function testPermissionDeletedEventFires(): void
    {
        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'posts:create',
            'guard_name' => 'web',
        ]);

        Event::fake([PermissionDeleted::class]);

        $permission->delete();

        Event::assertDispatched(
            PermissionDeleted::class,
            static fn (PermissionDeleted $event): bool => (string) $event->permission->getKey() === (string) $permission->getKey(),
        );
    }

    /**
     * Creating a policy dispatches `PolicyCreated`.
     *
     * @return void
     */
    public function testPolicyCreatedEventFires(): void
    {
        Event::fake([PolicyCreated::class]);

        $policy = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'allow-x',
            'document' => [
                'statements' => [['effect' => 'allow', 'actions' => ['x']]],
            ],
        ]);

        Event::assertDispatched(
            PolicyCreated::class,
            static fn (PolicyCreated $event): bool => $event->policy->is($policy),
        );
    }

    /**
     * Updating a policy dispatches `PolicyUpdated` with the change
     * set.
     *
     * @return void
     */
    public function testPolicyUpdatedEventCarriesChanges(): void
    {
        $policy = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'initial',
            'document' => [
                'statements' => [['effect' => 'allow', 'actions' => ['x']]],
            ],
        ]);

        Event::fake([PolicyUpdated::class]);

        $policy->description = 'Initial policy';
        $policy->save();

        Event::assertDispatched(
            PolicyUpdated::class,
            static fn (PolicyUpdated $event): bool => $event->policy->is($policy)
                && ($event->changes['description'] ?? null) === 'Initial policy',
        );
    }

    /**
     * Deleting a policy dispatches `PolicyDeleted`.
     *
     * @return void
     */
    public function testPolicyDeletedEventFires(): void
    {
        $policy = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'transient',
            'document' => [
                'statements' => [['effect' => 'allow', 'actions' => ['x']]],
            ],
        ]);

        Event::fake([PolicyDeleted::class]);

        $policy->delete();

        Event::assertDispatched(
            PolicyDeleted::class,
            static fn (PolicyDeleted $event): bool => (string) $event->policy->getKey() === (string) $policy->getKey(),
        );
    }
}
