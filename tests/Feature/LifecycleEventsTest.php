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
    /** Canonical description used across the role before/after diff scenarios. */
    private const string EDITOR_ROLE_DESCRIPTION = 'Editor role';

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
     * Updating a role dispatches `RoleUpdated` carrying both the
     * pre-save (`before`) and post-save (`after`) snapshots so an
     * audit consumer can render the diff without a second
     * round-trip (issue #73).
     *
     * @return void
     */
    public function testRoleUpdatedEventCarriesBeforeAndAfterDiff(): void
    {
        $role = Role::create([
            'id'          => (string) Str::uuid(),
            'name'        => 'editor',
            'guard_name'  => 'web',
            'description' => self::EDITOR_ROLE_DESCRIPTION,
        ]);

        Event::fake([RoleUpdated::class]);

        $role->description = 'Senior editor role';
        $role->save();

        Event::assertDispatched(
            RoleUpdated::class,
            static fn (RoleUpdated $event): bool => $event->role->is($role)
                && ($event->changes['before']['description'] ?? null) === self::EDITOR_ROLE_DESCRIPTION
                && ($event->changes['after']['description'] ?? null)  === 'Senior editor role',
        );
    }

    /**
     * The `before` map captures the pre-save value even when the
     * pre-save value was null (the row had no description before
     * the first set).
     *
     * @return void
     */
    public function testRoleUpdatedEventCarriesNullBeforeForFirstSet(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'editor',
            'guard_name' => 'web',
        ]);

        Event::fake([RoleUpdated::class]);

        $role->description = self::EDITOR_ROLE_DESCRIPTION;
        $role->save();

        Event::assertDispatched(
            RoleUpdated::class,
            static fn (RoleUpdated $event): bool => $event->role->is($role)
                && \array_key_exists('description', $event->changes['before'])
                && $event->changes['before']['description']          === null
                && ($event->changes['after']['description'] ?? null) === self::EDITOR_ROLE_DESCRIPTION,
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
     * the before/after diff (issue #73).
     *
     * @return void
     */
    public function testPermissionUpdatedEventCarriesBeforeAndAfterDiff(): void
    {
        $permission = Permission::create([
            'id'          => (string) Str::uuid(),
            'name'        => 'posts:create',
            'guard_name'  => 'web',
            'description' => 'Create posts',
        ]);

        Event::fake([PermissionUpdated::class]);

        $permission->description = 'Create blog posts';
        $permission->save();

        Event::assertDispatched(
            PermissionUpdated::class,
            static fn (PermissionUpdated $event): bool => $event->permission->is($permission)
                && ($event->changes['before']['description'] ?? null) === 'Create posts'
                && ($event->changes['after']['description'] ?? null)  === 'Create blog posts',
        );
    }

    /**
     * The `before` map captures null when the prior value was
     * null (first-time set on a previously empty column).
     *
     * @return void
     */
    public function testPermissionUpdatedEventCarriesNullBeforeForFirstSet(): void
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
                && \array_key_exists('description', $event->changes['before'])
                && $event->changes['before']['description']          === null
                && ($event->changes['after']['description'] ?? null) === 'Create posts',
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
     * Updating a policy dispatches `PolicyUpdated` with the
     * before/after diff (issue #73).
     *
     * @return void
     */
    public function testPolicyUpdatedEventCarriesBeforeAndAfterDiff(): void
    {
        $policy = Policy::create([
            'id'          => (string) Str::uuid(),
            'name'        => 'initial',
            'description' => 'Initial policy',
            'document'    => [
                'statements' => [['effect' => 'allow', 'actions' => ['x']]],
            ],
        ]);

        Event::fake([PolicyUpdated::class]);

        $policy->description = 'Updated policy';
        $policy->save();

        Event::assertDispatched(
            PolicyUpdated::class,
            static fn (PolicyUpdated $event): bool => $event->policy->is($policy)
                && ($event->changes['before']['description'] ?? null) === 'Initial policy'
                && ($event->changes['after']['description'] ?? null)  === 'Updated policy',
        );
    }

    /**
     * The `before` map captures null when the prior value was
     * null (first-time set on a previously empty column).
     *
     * @return void
     */
    public function testPolicyUpdatedEventCarriesNullBeforeForFirstSet(): void
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
                && \array_key_exists('description', $event->changes['before'])
                && $event->changes['before']['description']          === null
                && ($event->changes['after']['description'] ?? null) === 'Initial policy',
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
