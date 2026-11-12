<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Events\Role\Created as RoleCreated;
use SineMacula\Laravel\Authorization\Events\Role\Deleted as RoleDeleted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Role\PermissionGranted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Role\Updated as RoleUpdated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
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
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Services\SyncResult;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsAdministrator;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\AssertsDelegatedRefusals;
use Tests\Concerns\AssertsTransactions;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\ComparesReferences;
use Tests\Concerns\RacesDelegatedCalls;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Concerns\RecordsRowLocks;
use Tests\Concerns\RefusesThePackage;
use Tests\Concerns\ReportsEveryDecision;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Feature\Stubs\CustomPermission;
use Tests\Feature\Stubs\CustomRole;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenantTree;
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
    use ActsAsAdministrator, ActsAsTenant, AssertsDelegatedRefusals, AssertsTransactions, CatchesRefusals,
        ComparesReferences, RacesDelegatedCalls, ReadsDispatchedEvents, RecordsRowLocks, RefusesThePackage,
        ReportsEveryDecision, UsesAnAuthorizationConnection;

    /**
     * Report every decision, allows included: these tests observe the decisions
     * each call makes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->reportEveryDecision();
    }

    /**
     * A delegated revocation of a role's permission is decided under its action
     * before anything is written: an actor that may not take it is refused, by
     * name or by model, whether or not the role carries it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedPermissionRevocationIsRefusedWithoutItsAction(): void
    {
        $actor  = self::administrator([]);
        $editor = self::role('editor');
        $read   = Permission::query()->create(['name' => 'posts:read']);

        self::service()->grantPermission($editor, Permission::query()->create(['name' => 'posts:edit']));

        $noMatch = DecisionReason::NO_MATCH;

        self::assertDelegatedRefusal($noMatch, static fn (): int => self::service()->revokePermission($editor, 'posts:edit', $actor));
        self::assertDelegatedRefusal($noMatch, static fn (): int => self::service()->revokePermission($editor, 'posts:read', $actor));
        self::assertDelegatedRefusal($noMatch, static fn (): int => self::service()->revokePermission($editor, $read, $actor));
        self::assertSame([PackagePermissions::PERMISSION_REVOKE], self::actionsDecided());
    }

    /**
     * A delegated revocation of a permission the role does not carry is still
     * decided, on the revocation asked for, and revokes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedRevocationOfWhatIsNotCarriedIsStillDecided(): void
    {
        $actor  = self::administrator([PackagePermissions::PERMISSION_REVOKE]);
        $editor = self::role('editor');

        Permission::query()->create(['name' => 'posts:read']);

        self::fakePackageEvents();

        self::assertSame(0, self::service()->revokePermission($editor, 'posts:read', $actor));
        self::assertSame([PackagePermissions::PERMISSION_REVOKE], self::actionsDecided());
        self::assertSame([], self::changesDispatched());
    }

    /**
     * A delegated sync of a role's permissions is decided whole before anything
     * is written: one that grants to a role held by the actor's peer is refused
     * by rank (see `Impact`), one that only revokes or changes nothing is
     * refused to an actor without the action, and one that keeps what the role
     * carries live is made, changing nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedPermissionSyncIsDecidedBeforeAnythingIsWritten(): void
    {
        $admin  = self::administrator();
        $nobody = self::administrator([], 'nobody');
        $editor = self::role('editor');
        $empty  = self::role('empty');
        $edit   = Permission::query()->create(['name' => 'posts:edit']);
        $read   = Permission::query()->create(['name' => 'posts:read']);

        self::service()->grantPermission($editor, $edit);
        self::administrator([], 'peer');
        app(GrantService::class)->grantRole(StubIdentity::query()->findOrFail('peer'), $editor);

        self::assertDelegatedRefusal(DecisionReason::ADMINISTRATION_RANK, static fn (): mixed => self::service()->syncPermissions($editor, [$edit, $read], actor: $admin));
        self::assertDelegatedRefusal(DecisionReason::NO_MATCH, static fn (): mixed => self::service()->syncPermissions($editor, [], actor: $nobody));
        self::assertDelegatedRefusal(DecisionReason::NO_MATCH, static fn (): mixed => self::service()->syncPermissions($empty, [], actor: $nobody));
        self::assertDelegatedRefusal(DecisionReason::NO_MATCH, static fn (): mixed => self::service()->syncPermissions($editor, [$edit], actor: $nobody));
        self::assertFalse(self::service()->syncPermissions($editor, [$edit], actor: $admin)->isChange());
        self::assertSame([PackagePermissions::PERMISSION_GRANT, PackagePermissions::PERMISSION_GRANT], self::actionsDecided());
    }

    /**
     * A delegated change to a role is weighed on, and writes, the rows as
     * stored: a permission renamed and not saved is judged on its stored name,
     * granted or synced, and a role given a rank and not saved keeps its stored
     * rank when it is re-parented; a permission given by name is read as it is
     * looked up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedChangeToARoleIsWeighedOnTheStoredRows(): void
    {
        $admin  = self::administrator([PackagePermissions::PERMISSION_GRANT, PackagePermissions::ROLE_PARENT_SET, 'posts:read']);
        $editor = self::role('editor', ['rank' => 7]);
        $top    = self::role('top');

        app(GrantService::class)->grantRole(StubIdentity::query()->create(['id' => 'junior']), $editor);

        $delete        = Permission::query()->create(['name' => 'posts:delete']);
        $renamed       = Permission::query()->whereKey($delete->getKey())->firstOrFail();
        $renamed->name = 'posts:read';

        self::assertDelegatedRefusal(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, static fn (): mixed => self::service()->grantPermission($editor, $renamed, actor: $admin));
        self::assertDelegatedRefusal(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, static fn (): mixed => self::service()->syncPermissions($editor, [$renamed], actor: $admin));
        self::assertSame(0, DB::table('role_permissions')->count());

        self::assertSame(GrantOutcome::GRANTED, self::service()->grantPermission($editor, 'posts:read', actor: $admin));

        $editor->rank = 0;

        self::service()->setParent($editor, $top, $admin);

        self::assertSame(7, $editor->rank);
        self::assertSame(7, Role::query()->whereKey($editor->getKey())->firstOrFail()->rank);
        self::assertSame($top->getKey(), Role::query()->whereKey($editor->getKey())->firstOrFail()->parent_id);
    }

    /**
     * A change made without an actor is not judged, so the permission in hand
     * is granted as it is given, by its key, and reported by the name it holds,
     * never read again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeWithoutAnActorGrantsThePermissionAsGiven(): void
    {
        Event::fake([PermissionGranted::class]);

        $editor        = self::role('editor');
        $delete        = Permission::query()->create(['name' => 'posts:delete']);
        $renamed       = Permission::query()->whereKey($delete->getKey())->firstOrFail();
        $renamed->name = 'posts:purge';

        self::assertSame(GrantOutcome::GRANTED, self::service()->grantPermission($editor, $renamed));
        self::assertSame($delete->getKey(), DB::table('role_permissions')->value('permission_id'));
        Event::assertDispatched(PermissionGranted::class, static fn (PermissionGranted $event): bool => $event->permissionName === 'posts:purge');
    }

    /**
     * A role is created owned by the tenant given, as a model or a reference,
     * and by the platform for none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleIsCreatedOwnedByTheTenantGiven(): void
    {
        $tenant = self::createTenant('acme');
        $owned  = self::service()->create('editor', tenant: $tenant);
        $named  = self::service()->create('writer', tenant: new Reference('team', 'blue'));

        self::assertSame([$tenant->getMorphClass(), 'acme'], [$owned->tenant_type, $owned->tenant_id]);
        self::assertSame(['team', 'blue'], [$named->tenant_type, $named->tenant_id]);
        self::assertNull(self::service()->create('reader')->tenant_type);
        self::assertSame('blue', Role::query()->withoutGlobalScopes()->whereKey($named->getKey())->firstOrFail()->tenant_id);
    }

    /**
     * A delegated sync re-arms a kept permission as of the instant it judged
     * the grant's liveness at, so one it decided as live and unchanged is never
     * re-armed, even when it expires before it is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedPermissionSyncNeverReArmsAGrantItJudgedLive(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        $actor  = self::administrator([PackagePermissions::PERMISSION_GRANT]);
        $editor = self::role('editor');
        $edit   = Permission::query()->create(['name' => 'posts:edit']);

        self::service()->grantPermission($editor, $edit, Carbon::now()->addSecond());

        DB::listen(static function (QueryExecuted $query): void {
            if (\str_contains($query->sql, 'break_glass') || \preg_match('/expires_at\W*\s*>/', $query->sql) !== 1) {
                return;
            }

            Carbon::setTestNow(Carbon::now()->addMinute());
        });

        $result = self::service()->syncPermissions($editor, [$edit], actor: $actor);

        Carbon::setTestNow();

        self::assertSame([], $result->rearmed);
        self::assertSame('2026-07-01 12:00:01', DB::table('role_permissions')->value('expires_at'));
    }

    /**
     * A change to a platform role's permissions is decided at platform scope,
     * so an actor holding the action only in the tenant the request is in is
     * refused it, and one holding it platform-wide makes it from the platform,
     * which owns the role, but not from the tenant (D20); a change to a role an
     * ancestor of the request's tenant owns is out of scope.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeToARolesPermissionsIsDecidedInTheRolesScope(): void
    {
        [$parent, $child] = \array_map(self::createTenant(...), ['parent', 'child']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($child), Reference::of($parent)));

        $platform = self::role('editor');
        $owned    = Role::query()->withoutGlobalScopes()->create(['name' => 'owned', ...self::ownedBy($parent)]);
        $edit     = Permission::query()->create(['name' => 'posts:edit']);
        $revoke   = Permission::query()->create(['name' => PackagePermissions::PERMISSION_REVOKE]);
        $local    = StubIdentity::create(['id' => 'child-admin']);
        $wide     = StubIdentity::create(['id' => 'platform-admin']);

        self::service()->grantPermission($platform, $edit);
        self::service()->grantPermission($owned, $edit);
        app(GrantService::class)->grantPermission($local, $revoke, tenant: $child);
        app(GrantService::class)->grantPermission($wide, $revoke);

        $this->actAsTenant($child);

        self::assertDelegatedRefusal(DecisionReason::NO_MATCH, static fn (): int => self::service()->revokePermission($platform, $edit, ActingContext::for($local)));
        self::assertDelegatedRefusal(DecisionReason::TENANT_SCOPE, static fn (): int => self::service()->revokePermission($owned, $edit, ActingContext::for($local)));
        self::assertDelegatedRefusal(DecisionReason::ADMINISTRATION_OWNER, static fn (): int => self::service()->revokePermission($platform, $edit, ActingContext::for($wide)));
        self::assertSame(1, TenantScope::within(null, null, static fn (): int => self::service()->revokePermission($platform, $edit, ActingContext::for($wide))));
    }

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
     * A permission is granted until an expiry, stored in UTC: the same expiry
     * changes nothing, another changes it, and an expired grant is re-armed,
     * each change reported with the expiry before and after.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testGrantsAPermissionUntilAnExpiry(): void
    {
        $role       = self::role('editor');
        $permission = Permission::query()->create(['name' => 'posts:edit']);

        Event::fake([PermissionGranted::class, PermissionExpiryChanged::class]);

        self::assertSame(GrantOutcome::GRANTED, self::service()->grantPermission($role, $permission, Carbon::parse('2099-01-01 13:00:00', 'Europe/Paris')));
        self::assertSame('2099-01-01 12:00:00', DB::table('role_permissions')->value('expires_at'));
        self::assertSame(GrantOutcome::UNCHANGED, self::service()->grantPermission($role, $permission, Carbon::parse('2099-01-01 12:00:00', 'UTC')));
        self::assertSame(GrantOutcome::EXPIRY_CHANGED, self::service()->grantPermission($role, $permission));
        self::assertNull(DB::table('role_permissions')->value('expires_at'));

        DB::table('role_permissions')->update(['expires_at' => '2000-01-01 00:00:00']);

        self::assertSame(GrantOutcome::REARMED, self::service()->grantPermission($role, 'posts:edit', Carbon::parse('2099-06-01 00:00:00')));

        $granted = self::dispatchedEvents(PermissionGranted::class);
        $changed = self::dispatchedEvents(PermissionExpiryChanged::class);

        $expiries = \array_map(static fn (PermissionGranted $event): ?string => $event->expiresAt?->format('Y-m-d H:i:s e'), $granted);
        $changes  = \array_map(
            static fn (PermissionExpiryChanged $event): array => [$event->previousExpiresAt?->format('Y-m-d H:i:s'), $event->expiresAt?->format('Y-m-d H:i:s')],
            $changed,
        );

        self::assertSame(['2099-01-01 12:00:00 UTC', null, '2099-06-01 00:00:00 UTC'], $expiries);
        self::assertSame([['2099-01-01 12:00:00', null], ['2000-01-01 00:00:00', '2099-06-01 00:00:00']], $changes);
        self::assertTrue(self::refersTo($changed[0]->role, $role) && self::refersTo($changed[0]->permission, $permission));
        self::assertSame(['editor', 'posts:edit', null], [$changed[0]->roleName, $changed[0]->permissionName, $changed[0]->tenant]);
    }

    /**
     * A sync with an expiry grants what is missing until it, re-arms an expired
     * grant with it, and leaves a live grant as it is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASyncKeepsALiveGrantAndReArmsAnExpiredOne(): void
    {
        $role    = self::role('editor');
        $live    = Permission::query()->create(['name' => 'posts:edit']);
        $expired = Permission::query()->create(['name' => 'posts:read']);
        $missing = Permission::query()->create(['name' => 'posts:create']);

        self::service()->grantPermission($role, $live, Carbon::parse('2099-01-01 00:00:00'));
        self::service()->grantPermission($role, $expired, Carbon::parse('2000-01-01 00:00:00'));

        Event::fake([PermissionGranted::class, PermissionExpiryChanged::class, PermissionRevoked::class]);

        $result = self::service()->syncPermissions($role, [$live, $expired, $missing], Carbon::parse('2099-06-01 00:00:00'));

        self::assertSame([$missing->id], $result->granted);
        self::assertSame([$expired->id], $result->rearmed);
        self::assertSame([], $result->revoked);
        self::assertSame('2099-01-01 00:00:00', DB::table('role_permissions')->where('permission_id', $live->id)->value('expires_at'));
        self::assertSame('2099-06-01 00:00:00', DB::table('role_permissions')->where('permission_id', $expired->id)->value('expires_at'));
        self::assertSame('2099-06-01 00:00:00', DB::table('role_permissions')->where('permission_id', $missing->id)->value('expires_at'));
        Event::assertDispatchedTimes(PermissionGranted::class, 2);
        Event::assertDispatchedTimes(PermissionExpiryChanged::class, 1);
        Event::assertNotDispatched(PermissionRevoked::class);
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
     * Every role permission event one trusted sync dispatches carries the role
     * and permission by reference and by name, no actor, the sync's actions and
     * one operation id.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryEventOfOneSyncCarriesTheActorAndOneOperationId(): void
    {
        $role = self::role('editor', ['tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a']);
        $gone = Permission::query()->create(['name' => 'posts:delete']);

        Permission::query()->create(['name' => 'posts:edit']);
        Permission::query()->create(['name' => 'posts:create']);
        self::service()->grantPermission($role, $gone);

        Event::fake([PermissionGranted::class, PermissionRevoked::class]);

        self::service()->syncPermissions($role, ['posts:edit', 'posts:create']);

        $events = [...self::dispatchedEvents(PermissionGranted::class), ...self::dispatchedEvents(PermissionRevoked::class)];

        self::assertCount(3, $events);
        self::assertCount(1, \array_unique(\array_map(static fn (PermissionGranted|PermissionRevoked $event): string => $event->operation->id, $events)));

        foreach ($events as $event) {
            self::assertNull($event->operation->actor);
            self::assertTrue($event->operation->isTrusted);
            self::assertSame([PackagePermissions::PERMISSION_GRANT, PackagePermissions::PERMISSION_REVOKE], $event->operation->actions);
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
     * A trusted grant carries no actor; a delegated grant to a role no one
     * holds widens no one, and a delegated revocation only narrows, so each is
     * made, carrying the acting context's principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantAndARevocationCarryTheActor(): void
    {
        $admin      = self::administrator();
        $role       = self::role('editor');
        $permission = Permission::query()->create(['name' => 'posts:edit']);

        Event::fake([PermissionGranted::class, PermissionRevoked::class]);

        self::assertSame(GrantOutcome::GRANTED, self::service()->grantPermission($role, $permission, actor: $admin));

        self::service()->revokePermission($role, $permission, $admin);
        self::service()->grantPermission($role, $permission);

        Event::assertDispatched(PermissionGranted::class, static fn (PermissionGranted $event): bool => $event->operation->actor === null
            && self::refersTo($event->permission, $permission)
            && $event->permissionName === 'posts:edit'
            && $event->tenant         === null);
        Event::assertDispatched(PermissionGranted::class, static fn (PermissionGranted $event): bool => self::refersTo($event->operation->actor, $admin->principal()));
        Event::assertDispatched(PermissionRevoked::class, static fn (PermissionRevoked $event): bool => self::refersTo($event->operation->actor, $admin->principal()));
    }

    /**
     * Deleting a role through the service reports every grantee that held it,
     * as trusted work; a delegated deletion of a role a deny is attached to
     * would lift the deny from every holder, so it is refused as unprovable and
     * deletes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletingARoleReportsEveryGranteeThatHeldIt(): void
    {
        $admin = self::administrator();
        $role  = self::role('editor');

        app(GrantService::class)->grantRole(new Reference('user', '1'), $role);
        $deny = ['effect' => 'deny', 'actions' => ['posts:*']];

        app(GrantService::class)->attachPolicy(self::role('guarded'), Policy::create(['name' => 'denying', 'document' => ['statements' => [$deny]]]));

        Event::fake([RoleDeleted::class]);

        $refusal = self::refusalOf(static fn () => self::service()->delete('guarded', $admin));

        self::assertInstanceOf(AuthorizationException::class, $refusal);
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, $refusal->getReason());
        Event::assertNotDispatched(RoleDeleted::class);

        self::service()->delete('editor');

        Event::assertDispatchedTimes(RoleDeleted::class, 1);
        Event::assertDispatched(RoleDeleted::class, static fn (RoleDeleted $event): bool => $event->operation->actor === null
            && $event->operation->actions                                                                            === [PackagePermissions::ROLE_DELETE]
            && self::keysOf($event->grantees)                                                                        === ['user:1']);
    }

    /**
     * Re-parenting a role reports the change, as trusted work; a delegated
     * re-parenting away from a parent a deny is attached to would lift the deny
     * from every holder, so it is refused as unprovable and changes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReParentingReportsTheActor(): void
    {
        $admin   = self::administrator();
        $parent  = self::role('admin');
        $guarded = self::role('guarded');

        self::role('editor', ['parent_id' => $guarded->id]);
        app(GrantService::class)->attachPolicy($guarded, Policy::create(['name' => 'denying', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:*']]]]]));

        Event::fake([RoleUpdated::class]);

        $refusal = self::refusalOf(static fn (): Role => self::service()->setParent('editor', 'admin', $admin));

        self::assertInstanceOf(AuthorizationException::class, $refusal);
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, $refusal->getReason());
        self::assertSame($guarded->id, Role::query()->where('name', 'editor')->sole()->parent_id);

        self::service()->setParent('editor', 'admin');

        Event::assertDispatched(RoleUpdated::class, static fn (RoleUpdated $event): bool => $event->operation->actor === null
            && $event->operation->actions                                                                            === [PackagePermissions::ROLE_PARENT_SET]
            && ($event->changes['after']['parent_id'] ?? null)                                                       === $parent->id);
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
     * The same for a role's permissions: a permission a sync reads as carried,
     * revoked while it reads, is never written back, but decided as a grant to
     * the role's holder, refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleSyncNeverWritesBackAPermissionRevokedWhileItReads(): void
    {
        $actor  = self::administrator([PackagePermissions::PERMISSION_GRANT, PackagePermissions::PERMISSION_REVOKE]);
        $role   = self::role('billing');
        $revoke = static fn (): int => self::service()->revokePermission($role, 'billing:refund');

        self::service()->grantPermission($role, Permission::query()->create(['name' => 'billing:refund']));
        app(GrantService::class)->grantRole(StubIdentity::query()->create(['id' => 'user']), $role);

        $raced   = self::raceOnQuery('/^select permission_id from role_permissions .*expires_at/', $revoke);
        $refusal = self::refusalOf(static fn (): SyncResult => self::service()->syncPermissions($role, ['billing:refund'], actor: $actor));

        self::assertInstanceOf(AuthorizationException::class, $refusal);
        self::assertFalse($refusal->getDecision()?->isAllowed());
        self::assertCount(1, $raced);
        self::assertSame(0, DB::table('role_permissions')->where('role_id', $role->getKey())->count());
    }

    /**
     * A permission a role sync decided as carried live and finds gone when it
     * writes is never written back: the sync is tried again and decides the
     * permission as a grant to the role's holder, refused, leaving everything
     * as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleSyncNeverWritesBackAPermissionGoneByTheWrite(): void
    {
        $admin  = self::administrator([PackagePermissions::PERMISSION_GRANT, PackagePermissions::PERMISSION_REVOKE, 'posts:read']);
        $role   = self::role('billing');
        $revoke = static fn (): int => self::service()->revokePermission($role, 'billing:refund');

        self::service()->grantPermission($role, Permission::query()->create(['name' => 'billing:refund']));
        self::service()->grantPermission($role, Permission::query()->firstOrCreate(['name' => 'posts:read']));
        app(GrantService::class)->grantRole(StubIdentity::query()->create(['id' => 'user']), $role);

        $raced   = self::raceOnQuery('/^delete from role_permissions/', $revoke);
        $refusal = self::refusalOf(static fn (): SyncResult => self::service()->syncPermissions($role, ['billing:refund'], actor: $admin));

        self::assertInstanceOf(AuthorizationException::class, $refusal);
        self::assertCount(1, $raced);
        self::assertSame(['posts:read'], $role->getPermissions());
    }

    /**
     * A delegated change to what a role carries works on the role as stored,
     * read afresh, never on the caller's model, which it leaves as it was but
     * for its loaded permissions, dropped once the change commits, as a trusted
     * change drops them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedChangeLeavesTheCallersRoleAsItWasButItsPermissions(): void
    {
        $admin = self::administrator([PackagePermissions::PERMISSION_GRANT, PackagePermissions::PERMISSION_REVOKE, 'posts:read', 'posts:edit']);
        $role  = self::role('editor');
        $calls = [
            static fn (): GrantOutcome => self::service()->grantPermission($role, 'posts:read', actor: $admin),
            static fn (): int => self::service()->revokePermission($role, 'posts:read', $admin),
            static fn (): SyncResult => self::service()->syncPermissions($role, ['posts:edit'], actor: $admin),
        ];

        foreach ($calls as $call) {
            $role->load('permissions');
            $role->description = 'unsaved';

            $call();

            self::assertFalse($role->relationLoaded('permissions'));
            self::assertSame('unsaved', $role->description);
        }

        self::assertSame(['posts:edit'], $role->getPermissions());
    }

    /**
     * Once the package refuses, every operation of the service refuses by its
     * own guard, before it reads or writes anything.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryOperationRefusesOnceThePackageRefuses(): void
    {
        $role    = Role::create(['name' => 'editor']);
        $service = $this->container()->make(RoleService::class);

        Permission::create(['name' => 'posts:read']);

        $this->refuseThePackage();

        $this->assertEachRefused([
            'create'           => static fn () => $service->create('viewer'),
            'rename'           => static fn () => $service->rename($role, 'author'),
            'describe'         => static fn () => $service->describe($role, 'Edits'),
            'delete'           => static fn () => $service->delete($role),
            'find'             => static fn () => $service->find('editor'),
            'list'             => static fn () => $service->list(),
            'setParent'        => static fn () => $service->setParent($role, null),
            'grantPermission'  => static fn () => $service->grantPermission($role, 'posts:read'),
            'revokePermission' => static fn () => $service->revokePermission($role, 'posts:read'),
            'syncPermissions'  => static fn () => $service->syncPermissions($role, ['posts:read']),
        ]);
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
