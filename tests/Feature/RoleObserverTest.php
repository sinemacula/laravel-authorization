<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Events\Role\Created as RoleCreated;
use SineMacula\Laravel\Authorization\Events\Role\Deleted as RoleDeleted;
use SineMacula\Laravel\Authorization\Events\Role\Updated as RoleUpdated;
use SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\ParentGuardMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\ReservedRoleNameException;
use SineMacula\Laravel\Authorization\Exceptions\RoleHasChildrenException;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\ComparesReferences;
use Tests\Concerns\RecordsRowLocks;
use Tests\Feature\Stubs\CustomRole;
use Tests\TestCase;

/**
 * Feature tests pinning the role class the observer's hierarchy cycle check
 * resolves.
 *
 * With `authorization.models.role` pointed at an application subclass, the
 * proposed-parent lookup the observer runs before refusing a cycle hydrates
 * that subclass, never the shipped `Role`. The events the observer builds are
 * pinned too: what each carries, and the grantees a delete reports.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RoleObserver::class)]
#[CoversClass(RoleHierarchyCycleException::class)]
#[CoversClass(ReservedRoleNameException::class)]
final class RoleObserverTest extends TestCase
{
    use ActsAsTenant, CatchesRefusals, ComparesReferences, RecordsRowLocks;

    /** @var array{tenant_type: string, tenant_id: string} The owner columns of a tenant's role. */
    private const array TENANT = ['tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a'];

    /**
     * Point `authorization.models.role` at the subclass stub.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.models.role', CustomRole::class);
    }

    /**
     * A role with children is not deleted, even when the current tenant cannot
     * see a child, and once its children are gone it is (D18).
     *
     * @return void
     */
    public function testARoleWithChildrenIsNotDeleted(): void
    {
        $tenant = self::createTenant('tenant-a');
        $parent = Role::query()->create(['name' => 'parent']);
        $mine   = Role::query()->create(['name' => 'mine', 'parent_id' => $parent->id]);

        Role::query()->create(['name' => 'theirs', 'parent_id' => $parent->id, ...self::ownedBy($tenant)]);

        $refusal = self::refusalOf(static fn (): ?bool => $parent->delete());

        self::assertInstanceOf(RoleHasChildrenException::class, $refusal);
        self::assertSame(['mine', 'theirs'], $refusal->getChildNames());
        self::assertNotNull($parent->fresh());

        $mine->delete();
        Role::query()->withoutGlobalScopes()->where('name', 'theirs')->sole()->delete();

        self::assertTrue($parent->delete());
    }

    /**
     * Changing a role's guard re-checks its parent, its children and its
     * permissions, an expired grant included, and a change that leaves them
     * compatible is saved.
     *
     * @return void
     */
    public function testAGuardChangeIsCheckedAgainstTheRolesLinks(): void
    {
        $parent = Role::query()->create(['name' => 'parent', 'guard' => 'web']);
        $role   = Role::query()->create(['name' => 'role', 'parent_id' => $parent->id]);
        $child  = Role::query()->create(['name' => 'child', 'guard' => 'api', 'parent_id' => $role->id]);
        $holder = Role::query()->create(['name' => 'holder']);

        $holder->permissions()->attach(Permission::query()->create(['name' => 'posts:read', 'guard' => 'web'])->id, ['expires_at' => '2000-01-01 00:00:00']);

        $refusals = [[$role, 'api', ParentGuardMismatchException::class], [$role, 'web', ParentGuardMismatchException::class], [$holder, 'api', GuardMismatchException::class]];

        foreach ($refusals as [$target, $guard, $exception]) {
            $target->guard = $guard;

            self::assertInstanceOf($exception, self::refusalOf(static fn (): bool => $target->save()));

            $target->guard = null;
        }

        $child->guard = null;
        $child->save();

        $role->guard = 'web';
        $role->save();

        self::assertSame('web', $role->fresh()?->guard);
    }

    /**
     * Re-parenting a role under its own descendant is refused with the proposed
     * parent's name, read back through the configured subclass.
     *
     * @return void
     */
    public function testCycleCheckLooksUpProposedParentThroughConfiguredRoleClass(): void
    {
        $root  = $this->makeRole('admin');
        $child = $this->makeRole('editor', $root->id);

        $hydrated = $this->recordHydratedRoleClasses();

        $root->parent_id = $child->id;

        try {
            $root->save();
            self::fail('RoleHierarchyCycleException was not thrown.');
        } catch (RoleHierarchyCycleException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame('admin', $exception->getRoleName());
            self::assertSame('editor', $exception->getProposedParentName());
            // The parent is read once for the parity check, then the walk reads
            // it again under a lock, each as the configured class.
            self::assertSame([CustomRole::class, CustomRole::class], $hydrated->getArrayCopy());
        }
    }

    /**
     * A role is refused as its own parent, named as its own proposed parent.
     *
     * @return void
     */
    public function testARoleCannotBeItsOwnParent(): void
    {
        $role = $this->makeRole('admin');

        $role->parent_id = $role->id;

        $this->expectExceptionObject(new RoleHierarchyCycleException(roleName: 'admin', proposedParentName: 'admin'));

        $role->save();
    }

    /**
     * A parent deeper below the role is refused too, named by the proposed
     * parent rather than the role the walk reached.
     *
     * @return void
     */
    public function testAParentFurtherDownTheHierarchyIsRefused(): void
    {
        $root       = $this->makeRole('root');
        $child      = $this->makeRole('child', $root->id);
        $grandchild = $this->makeRole('grandchild', $child->id);

        $root->parent_id = $grandchild->id;

        $this->expectExceptionObject(new RoleHierarchyCycleException(roleName: 'root', proposedParentName: 'grandchild'));

        $root->save();
    }

    /**
     * A parent another tenant owns is refused, so no chain, and no cycle, runs
     * through two tenants' roles.
     *
     * @return void
     */
    public function testAParentAnotherTenantOwnsIsRefused(): void
    {
        $mine = CustomRole::query()->create(['name' => 'mine', ...self::ownedBy(self::createTenant('tenant-a'))]);

        $this->expectException(OwnerMismatchException::class);

        CustomRole::query()->create(['name' => 'theirs', ...self::ownedBy(self::createTenant('tenant-b')), 'parent_id' => $mine->id]);
    }

    /**
     * A chain above the proposed parent that loops without reaching the role is
     * corrupt, and the parent is refused rather than walked forever.
     *
     * @return void
     */
    public function testAParentWhoseChainLoopsIsRefused(): void
    {
        $first  = $this->makeRole('first');
        $second = $this->makeRole('second', $first->id);

        Role::query()->whereKey($first->id)->update(['parent_id' => $second->id]);

        $role = $this->makeRole('editor');

        $role->parent_id = $first->id;

        $this->expectExceptionObject(new RoleHierarchyCycleException(roleName: 'editor', proposedParentName: 'first'));

        $role->save();
    }

    /**
     * A role's parent may move to a role outside its descendants.
     *
     * @return void
     */
    public function testAParentOutsideTheRolesDescendantsIsAccepted(): void
    {
        $root    = $this->makeRole('root');
        $child   = $this->makeRole('child', $root->id);
        $another = $this->makeRole('another', $root->id);

        $child->parent_id = $another->id;
        $child->save();

        self::assertSame($another->id, $child->fresh()?->parent_id);
    }

    /**
     * The walk locks each ancestor it reads, in order up the chain.
     *
     * @return void
     */
    public function testTheWalkLocksEachAncestor(): void
    {
        $root   = $this->makeRole('root');
        $parent = $this->makeRole('parent', $root->id);
        $role   = $this->makeRole('editor');

        $locks = $this->recordRowLocks();

        $role->parent_id = $parent->id;
        $role->save();

        self::assertSame([['roles', [$parent->id]], ['roles', [$root->id]]], $locks->getArrayCopy());
    }

    /**
     * A chain that names an ancestor no row answers, as a parent key written
     * past the foreign key would, ends the walk there without an error.
     *
     * @return void
     */
    public function testAChainThatReachesAMissingAncestorEndsTheWalk(): void
    {
        $role            = $this->makeRole('editor');
        $role->parent_id = '00000000-0000-4000-8000-000000000000';

        $locks = $this->recordRowLocks();

        (new RoleObserver)->saving($role);

        self::assertSame([['roles', ['00000000-0000-4000-8000-000000000000']]], $locks->getArrayCopy());
    }

    /**
     * A save that leaves the parent alone does not walk the hierarchy.
     *
     * @return void
     */
    public function testASaveThatLeavesTheParentAloneDoesNotWalk(): void
    {
        $root  = $this->makeRole('root');
        $child = $this->makeRole('child', $root->id);

        $hydrated = $this->recordHydratedRoleClasses();

        $child->description = 'Changed';
        $child->save();

        self::assertSame([], $hydrated->getArrayCopy());
    }

    /**
     * Pairs of a platform role and a tenant role of the same name, by the
     * platform role's guard and system flag and the tenant role's guard, with
     * whether the pair is refused.
     *
     * @return iterable<string, array{string|null, bool, string|null, bool}>
     */
    public static function sharedNames(): iterable
    {
        yield 'system role, same guard' => ['web', true, 'web', true];
        yield 'system role, tenant guard-agnostic' => ['web', true, null, true];
        yield 'guard-agnostic system role' => [null, true, 'web', true];
        yield 'system role, another guard' => ['web', true, 'api', false];
        yield 'ordinary role, same guard' => ['web', false, 'web', false];
    }

    /**
     * A tenant role is refused when it would share its name with a platform
     * system role under a guard both answer.
     *
     * @param  string|null  $platformGuard
     * @param  bool  $isSystem
     * @param  string|null  $tenantGuard
     * @param  bool  $refused
     * @return void
     */
    #[DataProvider('sharedNames')]
    public function testATenantRoleCannotShareTheNameOfAPlatformSystemRole(?string $platformGuard, bool $isSystem, ?string $tenantGuard, bool $refused): void
    {
        CustomRole::query()->create(['name' => 'super-admin', 'guard' => $platformGuard, 'is_system' => $isSystem]);

        self::assertSame($refused, self::isRefused(['name' => 'super-admin', 'guard' => $tenantGuard] + self::TENANT));
        self::assertSame($refused ? 1 : 2, CustomRole::query()->withoutGlobalScopes()->count());
    }

    /**
     * A platform system role is refused when a tenant role already holds its
     * name under a guard both answer.
     *
     * @param  string|null  $platformGuard
     * @param  bool  $isSystem
     * @param  string|null  $tenantGuard
     * @param  bool  $refused
     * @return void
     */
    #[DataProvider('sharedNames')]
    public function testAPlatformSystemRoleCannotTakeATenantRolesName(?string $platformGuard, bool $isSystem, ?string $tenantGuard, bool $refused): void
    {
        CustomRole::query()->create(['name' => 'super-admin', 'guard' => $tenantGuard] + self::TENANT);

        self::assertSame($refused, self::isRefused(['name' => 'super-admin', 'guard' => $platformGuard, 'is_system' => $isSystem]));
    }

    /**
     * The refusal names the role whose save was refused.
     *
     * @return void
     */
    public function testTheRefusalNamesTheRole(): void
    {
        CustomRole::query()->create(['name' => 'super-admin', 'guard' => 'web', 'is_system' => true]);

        try {
            CustomRole::query()->create(['name' => 'super-admin', 'guard' => 'web'] + self::TENANT);
            self::fail('ReservedRoleNameException was not thrown.');
        } catch (ReservedRoleNameException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame('super-admin', $exception->getRoleName());
            self::assertSame(
                'Cannot save role \'super-admin\': a tenant role cannot share its name with a platform system role under a guard both answer.',
                $exception->getMessage(),
            );
        }
    }

    /**
     * A tenant role that becomes the platform system role of its own name is
     * not refused because of the row it was.
     *
     * @return void
     */
    public function testARoleIsNeverRefusedBecauseOfItself(): void
    {
        $role = CustomRole::query()->create(['name' => 'super-admin', 'guard' => 'web']);

        $role->forceFill(['is_system' => true])->save();

        self::assertTrue(CustomRole::query()->withoutGlobalScopes()->sole()->is_system);
    }

    /**
     * A save that changes none of the columns the check reads is not checked,
     * so a row that predates the rule can still be edited.
     *
     * @return void
     */
    public function testASaveThatLeavesTheCheckedColumnsAloneIsNotChecked(): void
    {
        $tenantRole = CustomRole::query()->create(['name' => 'super-admin', 'guard' => 'web'] + self::TENANT);

        CustomRole::query()->insert(['id' => '0f6a2c1e-6b2d-4f8a-9e3b-7c1d5a4f2e90', 'name' => 'super-admin', 'guard' => 'web', 'is_system' => true]);

        $tenantRole->description = 'Edited';
        $tenantRole->save();

        self::assertSame('Edited', CustomRole::query()->withoutGlobalScopes()->whereKey($tenantRole->id)->value('description'));
    }

    /**
     * Creating a role reports it as a snapshot: its reference, name, guard,
     * tenant and system flag, for an operation of its own with no actor.
     *
     * @return void
     */
    public function testReportsTheRoleCreated(): void
    {
        Event::fake([RoleCreated::class]);

        $role   = CustomRole::query()->create(['name' => 'editor', 'guard' => 'web'] + self::TENANT);
        $system = CustomRole::query()->create(['name' => 'admin', 'is_system' => true]);

        Event::assertDispatchedTimes(RoleCreated::class, 2);
        Event::assertDispatched(RoleCreated::class, static fn (RoleCreated $event): bool => self::refersTo($event->role, $role)
            && $event->name  === 'editor'
            && $event->guard === 'web'
            && self::refersTo($event->tenant, new Reference('stub_tenant', 'tenant-a'))
            && !$event->isSystem
            && $event->operation->actor === null);
        Event::assertDispatched(RoleCreated::class, static fn (RoleCreated $event): bool => self::refersTo($event->role, $system)
            && $event->guard  === null
            && $event->tenant === null
            && $event->isSystem);
    }

    /**
     * Updating a role reports the fields it changed, before and after, and the
     * role's name after the update.
     *
     * @return void
     */
    public function testReportsTheRoleUpdated(): void
    {
        $role = CustomRole::query()->create(['name' => 'editor', 'rank' => 1]);

        Event::fake([RoleUpdated::class]);

        $role->update(['name' => 'author', 'rank' => 2]);

        Event::assertDispatchedTimes(RoleUpdated::class, 1);
        Event::assertDispatched(RoleUpdated::class, static fn (RoleUpdated $event): bool => self::refersTo($event->role, $role)
            && $event->name                                                                === 'author'
            && \array_intersect_key($event->changes['before'], ['name' => 1, 'rank' => 1]) === ['name' => 'editor', 'rank' => 1]
            && \array_intersect_key($event->changes['after'], ['name' => 1, 'rank' => 1])  === ['name' => 'author', 'rank' => 2]);
    }

    /**
     * Deleting a role reports, in one event, every grantee that held it, in
     * order, and every permission it carried.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReportsTheRoleDeletedWithItsHoldersAndPermissions(): void
    {
        $role       = CustomRole::query()->create(['name' => 'editor']);
        $permission = Permission::query()->create(['name' => 'posts:edit']);

        $role->permissions()->attach($permission->id);

        foreach ([new Reference('user', '2'), new Reference('admin', '1'), new Reference('user', '10')] as $grantee) {
            app(GrantService::class)->grantRole($grantee, $role);
        }

        Event::fake([RoleDeleted::class]);

        $role->delete();

        Event::assertDispatchedTimes(RoleDeleted::class, 1);
        Event::assertDispatched(RoleDeleted::class, static fn (RoleDeleted $event): bool => self::refersTo($event->role, $role)
            && $event->name                      === 'editor'
            && self::keysOf($event->grantees)    === ['admin:1', 'user:10', 'user:2']
            && self::keysOf($event->permissions) === self::keysOf([Reference::of($permission)]));
    }

    /**
     * A role written through the role service reports the service call's actor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReportsTheActorOfTheServiceCall(): void
    {
        Event::fake([RoleCreated::class]);

        app(RoleService::class)->create('editor', actor: new Reference('user', 'admin-1'));

        Event::assertDispatched(RoleCreated::class, static fn (RoleCreated $event): bool => self::refersTo($event->operation->actor, new Reference('user', 'admin-1')));
    }

    /**
     * Record the class of every role model hydrated from here on.
     *
     * @return \ArrayObject<int, string>
     */
    private function recordHydratedRoleClasses(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $hydrated */
        $hydrated = new \ArrayObject;

        Event::listen('eloquent.retrieved: *', static function (string $event, array $payload) use ($hydrated): void {
            if (!$payload[0] instanceof Role) {
                return;
            }

            $hydrated->append($payload[0]::class);
        });

        return $hydrated;
    }

    /**
     * Determine whether creating a role with the given attributes is refused
     * for sharing a system role's name.
     *
     * @param  array<string, mixed>  $attributes
     * @return bool
     */
    private static function isRefused(array $attributes): bool
    {
        try {
            CustomRole::query()->create($attributes);
        } catch (ReservedRoleNameException) { // @phpstan-ignore catch.neverThrown
            return true;
        }

        return false;
    }

    /**
     * Create a role through the configured subclass.
     *
     * @param  string  $name
     * @param  string|null  $parentId
     * @return \Tests\Feature\Stubs\CustomRole
     */
    private function makeRole(string $name, ?string $parentId = null): CustomRole
    {
        return CustomRole::query()->create([
            'name'      => $name,
            'guard'     => 'web',
            'parent_id' => $parentId,
        ]);
    }
}
