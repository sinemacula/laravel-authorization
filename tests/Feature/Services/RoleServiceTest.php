<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Events\Role\Created as RoleCreated;
use SineMacula\Laravel\Authorization\Events\Role\Deleted as RoleDeleted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionGranted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Role\Updated as RoleUpdated;
use SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\RoleHasChildrenException;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Exceptions\SystemRoleProtectedException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Exceptions\UnsavedRecordException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\AssertsTransactions;
use Tests\Concerns\ComparesReferences;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Concerns\RecordsRowLocks;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Feature\Stubs\CustomPermission;
use Tests\Feature\Stubs\CustomRole;
use Tests\TestCase;

/**
 * Feature tests for `RoleService`, which creates, renames, describes,
 * re-parents, deletes and lists roles and grants their permissions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RoleService::class)]
final class RoleServiceTest extends TestCase
{
    use ActsAsTenant, AssertsTransactions, ComparesReferences, ReadsDispatchedEvents, RecordsRowLocks, UsesAnAuthorizationConnection;

    /**
     * Deleting a role with children is refused through the service too, and
     * leaves the role and its children as they were.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletingARoleWithChildrenIsRefused(): void
    {
        $parent = self::role('parent');

        self::role('child', ['parent_id' => $parent->id]);

        try {
            self::service()->delete($parent);
            self::fail('A role with children was deleted.');
        } catch (RoleHasChildrenException $exception) {
            self::assertSame('parent', $exception->getRoleName());
        }

        self::assertSame(2, Role::query()->count());
    }

    /**
     * A name finds the role the lookup ranks first under the guard, and an
     * unknown name is refused.
     *
     * @return void
     */
    public function testFindsARoleByName(): void
    {
        $agnostic = Role::query()->create(['name' => 'editor']);
        $web      = Role::query()->create(['name' => 'editor', 'guard' => 'web']);

        self::assertSame($web->id, self::service()->find('editor', 'web')->id);
        self::assertSame($agnostic->id, self::service()->find('editor', 'api')->id);

        $this->expectException(UnknownRoleException::class);

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
     * A role is created with its attributes, through the configured class, and
     * reported by the observer.
     *
     * @return void
     */
    public function testCreatesARole(): void
    {
        $this->config()->set('authorization.models.role', CustomRole::class);

        Event::fake([RoleCreated::class]);

        $role = self::service()->create('editor', 'web', 'Edits posts', 3);

        self::assertInstanceOf(CustomRole::class, $role);
        self::assertTrue($role->exists);
        self::assertTrue(Str::isUuid($role->id));
        self::assertSame(
            ['name' => 'editor', 'guard' => 'web', 'description' => 'Edits posts', 'rank' => 3],
            Role::query()->whereKey($role->id)->sole()->only(['name', 'guard', 'description', 'rank']),
        );
        Event::assertDispatched(RoleCreated::class);
    }

    /**
     * A role created with an id keeps it.
     *
     * @return void
     */
    public function testCreatesARoleWithTheGivenId(): void
    {
        $id = (string) Str::uuid();

        self::assertSame($id, self::service()->create('editor', id: $id)->id);
        self::assertTrue(Role::query()->whereKey($id)->exists());
    }

    /**
     * A role is written on the package's connection.
     *
     * @return void
     */
    public function testCreatesTheRoleOnThePackageConnection(): void
    {
        $this->useAnAuthorizationConnection();

        self::service()->create('editor');

        self::assertSame(1, self::authorizationConnection()->table('roles')->count());
        self::assertSame(0, DB::table('roles')->count());
    }

    /**
     * A role is renamed and described by model or by name.
     *
     * @return void
     */
    public function testRenamesAndDescribesARole(): void
    {
        $role = self::role('editor');

        self::assertSame('author', self::service()->rename('editor', 'author')->name);
        self::assertSame('Writes posts', self::service()->describe($role, 'Writes posts')->description);
        self::assertNull(self::service()->describe('author', null)->description);
        $fresh = $role->fresh();

        self::assertSame(['author', null], [$fresh?->name, $fresh?->description]);
    }

    /**
     * A system role keeps its protection through the service.
     *
     * @return void
     */
    public function testASystemRoleCannotBeRenamed(): void
    {
        self::role('admin', ['is_system' => true]);

        $this->expectException(SystemRoleProtectedException::class);

        self::service()->rename('admin', 'owner');
    }

    /**
     * A role is deleted by model or by name; an unknown name throws.
     *
     * @return void
     */
    public function testDeletesARole(): void
    {
        $role = self::role('editor');

        self::role('viewer');

        self::service()->delete($role);
        self::service()->delete('viewer');

        self::assertSame(0, Role::query()->count());

        $this->expectExceptionObject(new UnknownRoleException('ghost'));

        self::service()->delete('ghost');
    }

    /**
     * The roles are listed by name; with a guard, those of that guard or
     * guard-agnostic.
     *
     * @return void
     */
    public function testListsTheRoles(): void
    {
        self::role('viewer', ['guard' => 'api']);
        self::role('editor', ['guard' => 'web']);
        self::role('auditor');

        self::assertSame(['auditor', 'editor', 'viewer'], self::service()->list()->pluck('name')->all());
        self::assertSame(['auditor', 'viewer'], self::service()->list('api')->pluck('name')->all());
    }

    /**
     * A parent is set, by model or by name under the role's guard, and cleared.
     *
     * @return void
     */
    public function testSetsAndClearsAParent(): void
    {
        $role = self::role('editor', ['guard' => 'api']);

        self::role('author', ['guard' => 'web']);
        $parent = self::role('author', ['guard' => 'api']);

        self::assertSame($parent->id, self::service()->setParent($role, 'author')->parent_id);
        self::assertSame($parent->id, Role::query()->whereKey($role->id)->value('parent_id'));
        self::assertNull(self::service()->setParent($role, null)->parent_id);
        self::assertNull(Role::query()->whereKey($role->id)->value('parent_id'));
    }

    /**
     * Setting a parent locks the role and the parent first, in key order, and
     * outside the tenant scope.
     *
     * @return void
     */
    public function testSettingAParentLocksTheRoleAndTheParentFirst(): void
    {
        $role   = self::role('editor');
        $parent = self::role('author');
        $ids    = [$role->id, $parent->id];

        \sort($ids);

        $this->actAsTenant(self::createTenant('tenant-a'));

        $locks = $this->recordRowLocks();

        self::service()->setParent($role, $parent);

        self::assertSame([['roles', $ids], ['roles', [$parent->id]]], $locks->getArrayCopy());
    }

    /**
     * Setting a parent runs in one transaction on the package's connection: the
     * lookups and the locks as well as the save.
     *
     * @return void
     */
    public function testSettingAParentRunsInATransaction(): void
    {
        $this->useAnAuthorizationConnection();

        $role   = self::role('editor');
        $parent = self::role('author');

        self::assertAllInATransaction(static fn (): Role => self::service()->setParent('editor', 'author'));
        self::assertSame($parent->id, $role->fresh()?->parent_id);
    }

    /**
     * An unsaved role, as the role or as the parent, is refused, and the
     * hierarchy is left as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSettingAParentRefusesAnUnsavedRole(): void
    {
        $child  = self::role('child');
        $parent = self::role('parent');

        self::service()->setParent($child, $parent);

        foreach ([[$child, new Role(['name' => 'ghost'])], [new Role(['name' => 'ghost']), $parent]] as [$role, $proposed]) {
            try {
                self::service()->setParent($role, $proposed);
                self::fail('The unsaved role was not refused.');
            } catch (UnsavedRecordException $exception) {
                self::assertSame('The role service takes a saved role, not an unsaved ' . Role::class . '.', $exception->getMessage());
            }
        }

        self::assertSame($parent->id, Role::query()->whereKey($child->id)->value('parent_id'));
        self::assertSame(2, Role::query()->count());
    }

    /**
     * An unsaved role is refused by every change, so none creates a role
     * outside `create()`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChangesRefuseAnUnsavedRole(): void
    {
        $permission = Permission::query()->create(['name' => 'posts:edit']);
        $calls      = [
            'rename'   => static fn (RoleService $service, Role $role): mixed => $service->rename($role, 'b'),
            'describe' => static fn (RoleService $service, Role $role): mixed => $service->describe($role, 'b'),
            'delete'   => static function (RoleService $service, Role $role): void {
                $service->delete($role);
            },
            'grantPermission'  => static fn (RoleService $service, Role $role): mixed => $service->grantPermission($role, $permission),
            'revokePermission' => static fn (RoleService $service, Role $role): mixed => $service->revokePermission($role, $permission),
            'syncPermissions'  => static fn (RoleService $service, Role $role): mixed => $service->syncPermissions($role, [$permission]),
        ];

        foreach ($calls as $name => $call) {
            try {
                $call(self::service(), new Role(['name' => 'a']));
                self::fail("The {$name} did not refuse the unsaved role.");
            } catch (UnsavedRecordException $exception) {
                self::assertSame('role', $exception->getKind());
            }
        }

        self::assertSame(0, Role::query()->count());
        self::assertSame(0, DB::table('role_permissions')->count());
    }

    /**
     * A parent that would close a cycle is refused, and nothing is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAParentThatClosesACycle(): void
    {
        $root  = self::role('root');
        $child = self::role('child', ['parent_id' => $root->id]);

        try {
            self::service()->setParent($root, $child);
            self::fail('The cycle was not refused.');
        } catch (RoleHierarchyCycleException $exception) {
            self::assertSame('child', $exception->getProposedParentName());
        }

        self::assertNull($root->fresh()?->parent_id);
    }

    /**
     * A parent another tenant owns is refused, so no chain, and no cycle, runs
     * through two tenants' roles.
     *
     * @return void
     */
    public function testRefusesAParentAnotherTenantOwns(): void
    {
        $mine   = self::role('mine', self::ownedBy(self::createTenant('tenant-a')));
        $theirs = self::role('theirs', self::ownedBy(self::createTenant('tenant-b')));

        $this->expectException(OwnerMismatchException::class);

        self::service()->setParent($theirs, $mine);
    }

    /**
     * A permission is granted to a role by name under the role's guard, once:
     * granting it again changes nothing and dispatches nothing.
     *
     * @return void
     */
    public function testGrantsAPermissionOnce(): void
    {
        $role = self::role('editor', ['guard' => 'api']);

        Permission::query()->create(['name' => 'posts:edit', 'guard' => 'web']);
        $permission = Permission::query()->create(['name' => 'posts:edit', 'guard' => 'api']);

        Event::fake([PermissionGranted::class]);

        self::assertCount(0, $role->permissions);
        self::assertSame(GrantOutcome::GRANTED, self::service()->grantPermission($role, 'posts:edit'));
        self::assertFalse($role->relationLoaded('permissions'));
        self::assertSame(GrantOutcome::UNCHANGED, self::service()->grantPermission($role, $permission));
        self::assertSame([$permission->id], DB::table('role_permissions')->pluck('permission_id')->all());
        Event::assertDispatchedTimes(PermissionGranted::class, 1);
        Event::assertDispatched(
            PermissionGranted::class,
            static fn (PermissionGranted $event): bool => self::refersTo($event->role, $role) && self::refersTo($event->permission, $permission),
        );
    }

    /**
     * A concurrent duplicate written between the check and the attachment is
     * reported as unchanged rather than raising.
     *
     * @return void
     */
    public function testAConcurrentDuplicateIsUnchangedRatherThanRaising(): void
    {
        $role       = self::role('editor');
        $permission = Permission::query()->create(['name' => 'posts:edit']);
        $written    = false;

        DB::listen(static function (QueryExecuted $query) use (&$written, $role, $permission): void {
            if ($written || !\str_contains($query->sql, 'exists')) {
                return;
            }

            $written = true;

            DB::table('role_permissions')->insert(['role_id' => $role->id, 'permission_id' => $permission->id]);
        });

        Event::fake([PermissionGranted::class]);

        self::assertSame(GrantOutcome::UNCHANGED, self::service()->grantPermission($role, $permission));
        self::assertSame(1, DB::table('role_permissions')->count());
        Event::assertNotDispatched(PermissionGranted::class);
    }

    /**
     * Guard parity still holds through the service.
     *
     * @return void
     */
    public function testGuardParityHolds(): void
    {
        $role       = self::role('editor', ['guard' => 'web']);
        $permission = Permission::query()->create(['name' => 'posts:edit', 'guard' => 'api']);

        $this->expectException(GuardMismatchException::class);

        self::service()->grantPermission($role, $permission);
    }

    /**
     * A permission is revoked from a role once; revoking it again changes
     * nothing and dispatches nothing.
     *
     * @return void
     */
    public function testRevokesAPermissionOnce(): void
    {
        $role       = self::role('editor');
        $permission = Permission::query()->create(['name' => 'posts:edit']);

        self::service()->grantPermission($role, $permission);

        Event::fake([PermissionRevoked::class]);

        self::assertCount(1, $role->permissions);
        self::assertSame(1, self::service()->revokePermission($role, 'posts:edit'));
        self::assertFalse($role->relationLoaded('permissions'));
        self::assertSame(0, self::service()->revokePermission($role, $permission));
        self::assertSame(0, DB::table('role_permissions')->count());
        Event::assertDispatchedTimes(PermissionRevoked::class, 1);
    }

    /**
     * Revoking a name revokes every permission of that name the role carries,
     * including a platform permission when the tenant owns one of the same
     * name, with one event each.
     *
     * @return void
     */
    public function testRevokingANameRevokesEveryHeldPermissionOfIt(): void
    {
        $tenant   = self::createTenant('tenant-a');
        $role     = self::role('editor', self::ownedBy($tenant));
        $platform = Permission::query()->create(['name' => 'posts:edit']);
        $owned    = Permission::query()->create(['name' => 'posts:edit', ...self::ownedBy($tenant)]);
        $other    = Permission::query()->create(['name' => 'posts:delete']);

        self::service()->grantPermission($role, $platform);
        self::service()->grantPermission($role, $other);

        $this->actAsTenant($tenant);

        Event::fake([PermissionRevoked::class]);

        self::assertSame(1, self::service()->revokePermission($role, 'posts:edit'));
        self::assertSame([$other->id], DB::table('role_permissions')->pluck('permission_id')->all());
        Event::assertDispatchedTimes(PermissionRevoked::class, 1);
        Event::assertDispatched(PermissionRevoked::class, static fn (PermissionRevoked $event): bool => self::refersTo($event->permission, $platform));

        self::service()->grantPermission($role, $platform);
        self::service()->grantPermission($role, $owned);

        self::assertSame(2, self::service()->revokePermission($role, 'posts:edit'));
        self::assertSame([$other->id], DB::table('role_permissions')->pluck('permission_id')->all());
        Event::assertDispatchedTimes(PermissionRevoked::class, 3);
    }

    /**
     * A name in a sync keeps every permission of that name the role carries,
     * and only when it carries none is the one the lookup ranks first granted.
     *
     * @return void
     */
    public function testASyncNameKeepsTheHeldPermissionsOfIt(): void
    {
        $tenant   = self::createTenant('tenant-a');
        $role     = self::role('editor', self::ownedBy($tenant));
        $platform = Permission::query()->create(['name' => 'posts:edit']);
        $owned    = Permission::query()->create(['name' => 'posts:edit', ...self::ownedBy($tenant)]);

        self::service()->grantPermission($role, $platform);

        $this->actAsTenant($tenant);

        self::assertFalse(self::service()->syncPermissions($role, ['posts:edit'])->isChange());
        self::assertSame([$platform->id], DB::table('role_permissions')->pluck('permission_id')->all());

        self::service()->syncPermissions($role, []);

        self::assertSame([$owned->id], self::service()->syncPermissions($role, ['posts:edit'])->granted);
    }

    /**
     * Granting and revoking a role's permission each run in one transaction on
     * the package's connection: the lookups as well as the write.
     *
     * @return void
     */
    public function testGrantingAndRevokingAPermissionRunInATransaction(): void
    {
        $this->useAnAuthorizationConnection();

        self::role('editor');
        Permission::query()->create(['name' => 'posts:edit']);

        self::assertSame(GrantOutcome::GRANTED, self::assertAllInATransaction(static fn (): GrantOutcome => self::service()->grantPermission('editor', 'posts:edit')));
        self::assertSame(1, self::assertAllInATransaction(static fn (): int => self::service()->revokePermission('editor', 'posts:edit')));
        self::assertSame(0, self::authorizationConnection()->table('role_permissions')->count());
    }

    /**
     * An unknown permission name throws.
     *
     * @return void
     */
    public function testAnUnknownPermissionNameThrows(): void
    {
        self::role('editor');

        $this->expectExceptionObject(new UnknownPermissionException('ghost'));

        self::service()->grantPermission('editor', 'ghost');
    }

    /**
     * A sync grants what is missing and revokes what is not listed, with one
     * event per change, and reports both.
     *
     * @return void
     */
    public function testSyncsARolesPermissions(): void
    {
        $this->config()->set('authorization.models.permission', CustomPermission::class);

        $role   = self::role('editor');
        $kept   = Permission::query()->create(['name' => 'posts:edit']);
        $gone   = Permission::query()->create(['name' => 'posts:delete']);
        $joined = Permission::query()->create(['name' => 'posts:create']);

        self::service()->grantPermission($role, $kept);
        self::service()->grantPermission($role, $gone);

        Event::fake([PermissionGranted::class, PermissionRevoked::class]);

        $result = self::service()->syncPermissions($role, [$kept, 'posts:create']);

        self::assertSame([$joined->id], $result->granted);
        self::assertSame([], $result->rearmed);
        self::assertSame([$gone->id], $result->revoked);
        self::assertEqualsCanonicalizing([$kept->id, $joined->id], DB::table('role_permissions')->pluck('permission_id')->all());
        Event::assertDispatchedTimes(PermissionGranted::class, 1);
        Event::assertDispatched(PermissionGranted::class, static fn (PermissionGranted $event): bool => $event->permission->type === (new CustomPermission)->getMorphClass()
            && $event->permission->id                                                                                            === $joined->id);
        Event::assertDispatchedTimes(PermissionRevoked::class, 1);
        Event::assertDispatched(
            PermissionRevoked::class,
            static fn (PermissionRevoked $event): bool => self::refersTo($event->role, $role) && $event->permission->id === $gone->id,
        );
        self::assertFalse(self::service()->syncPermissions($role, [$kept, $joined])->isChange());
    }

    /**
     * A sync reports a revoked permission another tenant owns.
     *
     * @return void
     */
    public function testASyncReportsARevokedPermissionOfAnotherTenant(): void
    {
        $tenant = self::createTenant('tenant-a');
        $role   = self::role('editor', self::ownedBy($tenant));
        $other  = Permission::query()->create(['name' => 'posts:edit', ...self::ownedBy($tenant)]);

        self::service()->grantPermission($role, $other);

        $this->actAsTenant(self::createTenant('tenant-b'));

        Event::fake([PermissionRevoked::class]);

        self::assertSame([$other->id], self::service()->syncPermissions($role, [])->revoked);
        Event::assertDispatched(PermissionRevoked::class, static fn (PermissionRevoked $event): bool => self::refersTo($event->permission, $other));
    }

    /**
     * A sync refuses an entry that is not a permission and writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASyncRefusesAnEntryThatIsNotAPermission(): void
    {
        $role       = self::role('editor');
        $permission = Permission::query()->create(['name' => 'posts:edit']);

        self::service()->grantPermission($role, $permission);

        try {
            self::service()->syncPermissions($role, [self::role('viewer')]); // @phpstan-ignore argument.type
            self::fail('The sync was not refused.');
        } catch (InvalidGrantTargetException $exception) {
            self::assertSame('permission', $exception->getKind());
        }

        self::assertSame([$permission->id], DB::table('role_permissions')->pluck('permission_id')->all());
    }

    /**
     * A sync that fails part-way rolls back what it wrote before the failure.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASyncThatFailsPartWayRollsBack(): void
    {
        $role   = self::role('editor');
        $kept   = Permission::query()->create(['name' => 'posts:edit']);
        $listed = Permission::query()->create(['name' => 'posts:create']);

        self::service()->grantPermission($role, $kept);

        DB::listen(static function (QueryExecuted $query): void {
            if (!\str_starts_with($query->sql, 'insert into') || !\str_contains($query->sql, 'role_permissions')) {
                return;
            }

            throw new \RuntimeException('Write failed.');
        });

        try {
            self::service()->syncPermissions($role, [$listed]);
            self::fail('The sync did not fail.');
        } catch (\RuntimeException $exception) {
            self::assertSame('Write failed.', $exception->getMessage());
        }

        self::assertSame([$kept->id], DB::table('role_permissions')->pluck('permission_id')->all());
    }

    /**
     * Every role permission event one sync dispatches carries the role and
     * permission by reference and by name, the caller's actor and one operation
     * id.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryEventOfOneSyncCarriesTheActorAndOneOperationId(): void
    {
        $role  = self::role('editor', ['tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a']);
        $gone  = Permission::query()->create(['name' => 'posts:delete']);
        $actor = new Reference('user', 'admin-1');

        Permission::query()->create(['name' => 'posts:edit']);
        Permission::query()->create(['name' => 'posts:create']);
        self::service()->grantPermission($role, $gone);

        Event::fake([PermissionGranted::class, PermissionRevoked::class]);

        self::service()->syncPermissions($role, ['posts:edit', 'posts:create'], $actor);

        $events = [...self::dispatchedEvents(PermissionGranted::class), ...self::dispatchedEvents(PermissionRevoked::class)];

        self::assertCount(3, $events);
        self::assertCount(1, \array_unique(\array_map(static fn (PermissionGranted|PermissionRevoked $event): string => $event->operation->id, $events)));

        foreach ($events as $event) {
            self::assertTrue(self::refersTo($event->operation->actor, $actor));
            self::assertTrue(self::refersTo($event->role, $role));
            self::assertSame('editor', $event->roleName);
            self::assertTrue(self::refersTo($event->tenant, new Reference('stub_tenant', 'tenant-a')));
        }

        Event::assertDispatched(
            PermissionRevoked::class,
            static fn (PermissionRevoked $event): bool => self::refersTo($event->permission, $gone) && $event->permissionName === 'posts:delete',
        );
    }

    /**
     * A grant and a revocation carry the caller's actor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantAndARevocationCarryTheActor(): void
    {
        $role       = self::role('editor');
        $permission = Permission::query()->create(['name' => 'posts:edit']);
        $actor      = new Reference('user', 'admin-1');

        Event::fake([PermissionGranted::class, PermissionRevoked::class]);

        self::service()->grantPermission($role, $permission, $actor);
        self::service()->revokePermission($role, $permission, $actor);

        Event::assertDispatched(PermissionGranted::class, static fn (PermissionGranted $event): bool => self::refersTo($event->operation->actor, $actor)
            && self::refersTo($event->permission, $permission)
            && $event->permissionName === 'posts:edit'
            && $event->tenant         === null);
        Event::assertDispatched(PermissionRevoked::class, static fn (PermissionRevoked $event): bool => self::refersTo($event->operation->actor, $actor));
    }

    /**
     * Deleting a role through the service reports, with the caller's actor,
     * every grantee that held it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletingARoleReportsEveryGranteeThatHeldIt(): void
    {
        $role  = self::role('editor');
        $actor = new Reference('user', 'admin-1');

        app(GrantService::class)->grantRole(new Reference('user', '1'), $role);

        Event::fake([RoleDeleted::class]);

        self::service()->delete('editor', $actor);

        Event::assertDispatchedTimes(RoleDeleted::class, 1);
        Event::assertDispatched(RoleDeleted::class, static fn (RoleDeleted $event): bool => self::refersTo($event->operation->actor, $actor)
            && self::keysOf($event->grantees) === ['user:1']);
    }

    /**
     * Re-parenting a role reports the change with the caller's actor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReParentingReportsTheActor(): void
    {
        $parent = self::role('admin');
        $actor  = new Reference('user', 'admin-1');

        self::role('editor');

        Event::fake([RoleUpdated::class]);

        self::service()->setParent('editor', 'admin', $actor);

        Event::assertDispatched(RoleUpdated::class, static fn (RoleUpdated $event): bool => self::refersTo($event->operation->actor, $actor)
            && ($event->changes['after']['parent_id'] ?? null) === $parent->id);
    }

    /**
     * A role created inside an enclosing transaction that rolls back is never
     * reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACreateRolledBackWithItsEnclosingTransactionIsNeverReported(): void
    {
        Event::fake([RoleCreated::class]);

        try {
            DB::transaction(static function (): never {
                self::service()->create('editor');

                throw new \RuntimeException('Rolled back.');
            });
        } catch (\RuntimeException) {
            // The enclosing transaction rolled back.
        }

        self::assertSame(0, Role::query()->count());
        Event::assertNotDispatched(RoleCreated::class);
    }

    /**
     * Return the role service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\RoleService
     */
    private static function service(): RoleService
    {
        return app(RoleService::class);
    }

    /**
     * Create a role.
     *
     * @param  string  $name
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function role(string $name, array $attributes = []): Role
    {
        return Role::query()->create(['name' => $name, ...$attributes]);
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
