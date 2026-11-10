<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Events\Identity\BoundaryRemoved;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionExpired;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyExpired;
use SineMacula\Laravel\Authorization\Events\Identity\RoleExpired;
use SineMacula\Laravel\Authorization\Events\Identity\RoleRevoked;
use SineMacula\Laravel\Authorization\Events\Policy\Deleted as PolicyDeleted;
use SineMacula\Laravel\Authorization\Events\Resource\PolicyDetached as ResourcePolicyDetached;
use SineMacula\Laravel\Authorization\Events\Role\PermissionExpired as RolePermissionExpired;
use SineMacula\Laravel\Authorization\Exceptions\SystemPolicyProtectedException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantPruner;
use SineMacula\Laravel\Authorization\Services\PruneResult;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Concerns\RefusesThePackage;
use Tests\Feature\Stubs\NumberedIdentity;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for removing expired grants, the grants, boundaries and inline
 * policies of grantees that no longer exist, and the resource policies of
 * records that no longer exist.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantPruner::class)]
#[CoversClass(PruneResult::class)]
final class GrantPrunerTest extends TestCase
{
    use ReadsDispatchedEvents, RefusesThePackage;

    /**
     * Start the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-07-01 12:00:00');
    }

    /**
     * Reset the clock and the morph map.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * Expired grants of every kind, a role's grants of permissions included,
     * are removed and reported, with no actor, the scope and the expiry; live
     * and permanent grants stay.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovesExpiredGrantsOfEveryKind(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $role   = Role::create(['name' => 'editor']);
        $tenant = new Reference('stub_tenant', 'tenant-a');

        $user->assignRole($role, Carbon::parse('2026-07-01 11:00:00'), $tenant);
        $user->assignRole(Role::create(['name' => 'viewer']));
        $user->givePermission(Permission::create(['name' => 'posts:edit']), Carbon::parse('2026-07-01 11:30:00'));
        $user->givePermission(Permission::create(['name' => 'posts:read']), Carbon::parse('2026-07-01 13:00:00'));
        $user->attachPolicy(Policy::create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]), Carbon::parse('2026-07-01 12:00:00'));
        $role->givePermission(Permission::create(['name' => 'posts:delete']), Carbon::parse('2026-07-01 10:00:00'));
        $role->givePermission('posts:read', Carbon::parse('2026-07-01 13:00:00'));

        Event::fake();

        $result = self::pruner()->prune(1000);

        self::assertSame(4, $result->expired);
        self::assertSame(0, $result->orphaned);
        self::assertSame(['viewer'], Role::query()->whereKey(DB::table('authorizable_roles')->pluck('role_id'))->pluck('name')->all());
        self::assertSame(1, DB::table('authorizable_permissions')->count());
        self::assertSame(0, DB::table('authorizable_policies')->count());

        $expired = self::dispatchedEvents(RoleExpired::class);

        self::assertCount(1, $expired);
        self::assertNull($expired[0]->operation->actor);
        self::assertSame('editor', $expired[0]->name);
        self::assertEquals($tenant, $expired[0]->scope->tenant);
        self::assertSame('2026-07-01 11:00:00', $expired[0]->expiredAt->format('Y-m-d H:i:s'));
        self::assertSame('UTC', $expired[0]->expiredAt->getTimezone()->getName());
        Event::assertDispatchedTimes(PermissionExpired::class, 1);
        Event::assertDispatchedTimes(PolicyExpired::class, 1);
        self::assertSame(['posts:read'], $role->getPermissions());

        $lapsed = self::dispatchedEvents(RolePermissionExpired::class);

        self::assertCount(1, $lapsed);
        self::assertNull($lapsed[0]->operation->actor);
        self::assertSame(['editor', 'posts:delete', null], [$lapsed[0]->roleName, $lapsed[0]->permissionName, $lapsed[0]->tenant]);
        self::assertSame($role->id, $lapsed[0]->role->id);
        self::assertSame('2026-07-01 10:00:00 UTC', $lapsed[0]->expiredAt->format('Y-m-d H:i:s e'));
    }

    /**
     * Expired grants are removed a chunk at a time until none is left, each
     * chunk one operation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovesExpiredGrantsInChunks(): void
    {
        for ($i = 0; $i < 5; $i++) {
            StubIdentity::create(['id' => "user-{$i}"])->assignRole(Role::create(['name' => "role-{$i}"]), Carbon::parse('2026-07-01 11:00:00'));
        }

        Event::fake();

        self::assertSame(5, self::pruner()->prune(2)->expired);
        self::assertSame(0, DB::table('authorizable_roles')->count());

        $operations = \array_unique(\array_map(static fn (RoleExpired $event): string => $event->operation->id, self::dispatchedEvents(RoleExpired::class)));

        self::assertCount(3, $operations);
    }

    /**
     * Each expired grant of the same grantee and target is removed and reported
     * in its own scope, so grants that differ only in their tenant or
     * application are told apart.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovesEachExpiredGrantInItsOwnScope(): void
    {
        $user  = StubIdentity::create(['id' => 'user-1']);
        $role  = Role::create(['name' => 'editor']);
        $until = Carbon::parse('2026-07-01 11:00:00');

        $user->assignRole($role, $until);
        $user->assignRole($role, $until, new Reference('stub_team', '1'));
        $user->assignRole($role, $until, new Reference('stub_org', '1'), false);

        DB::table('authorizable_roles')->insert([
            'role_id'           => $role->id,
            'authorizable_type' => $user->getMorphClass(),
            'authorizable_id'   => 'user-1',
            'application'       => 'admin',
            'expires_at'        => '2026-07-01 11:00:00',
        ]);

        Event::fake();

        self::assertSame(4, self::pruner()->prune(1000)->expired);
        self::assertSame(0, DB::table('authorizable_roles')->count());

        $scopes = \array_map(static fn (RoleExpired $event): string => \sprintf(
            '%s:%s:%s:%s',
            $event->scope->tenant?->type,
            $event->scope->tenant?->id,
            $event->scope->application,
            $event->scope->includeSubtree ? 'below' : 'alone',
        ), self::dispatchedEvents(RoleExpired::class));

        self::assertEqualsCanonicalizing([':::below', 'stub_team:1::below', 'stub_org:1::alone', '::admin:below'], $scopes);
    }

    /**
     * A grant re-armed between the read of the expired grants and its removal
     * is kept, and nothing is reported, a role's grant of a permission as well.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testKeepsAGrantReArmedWhileThePruneRuns(): void
    {
        $role = Role::create(['name' => 'editor']);

        StubIdentity::create(['id' => 'user-1'])->assignRole($role, Carbon::parse('2026-07-01 11:00:00'));
        $role->givePermission(Permission::create(['name' => 'posts:edit']), Carbon::parse('2026-07-01 11:00:00'));

        $rearmed = [];

        DB::listen(static function (QueryExecuted $query) use (&$rearmed): void {
            foreach (['authorizable_roles', 'role_permissions'] as $table) {
                if (isset($rearmed[$table]) || !\str_starts_with($query->sql, 'select') || !\str_contains($query->sql, $table)) {
                    continue;
                }

                $rearmed[$table] = true;

                DB::table($table)->update(['expires_at' => '2026-07-02 12:00:00']);
            }
        });

        Event::fake();

        self::assertSame(0, self::pruner()->prune(1000)->expired);
        self::assertSame(1, DB::table('authorizable_roles')->count());
        self::assertSame(1, DB::table('role_permissions')->count());
        Event::assertNotDispatched(RoleExpired::class);
        Event::assertNotDispatched(RolePermissionExpired::class);
    }

    /**
     * Pretending counts what would be removed and removes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPretendingCountsWithoutRemoving(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $gone = StubIdentity::create(['id' => 'user-2']);

        $user->assignRole(Role::create(['name' => 'editor']), Carbon::parse('2026-07-01 11:00:00'));
        $gone->assignRole(Role::create(['name' => 'viewer']));
        Role::create(['name' => 'author'])->givePermission(Permission::create(['name' => 'posts:edit']), Carbon::parse('2026-07-01 11:00:00'));
        $gone->givePermission(Permission::create(['name' => 'posts:read']));

        DB::table('stub_identities')->where('id', 'user-2')->delete();

        Event::fake();

        $result = self::pruner()->prune(1000, true);

        self::assertSame(2, $result->expired);
        self::assertSame(1, DB::table('role_permissions')->count());
        self::assertSame(2, $result->orphaned);
        self::assertSame(2, DB::table('authorizable_roles')->count());
        self::assertSame(1, DB::table('authorizable_permissions')->count());
        Event::assertNothingDispatched();
    }

    /**
     * The grants of a grantee that no longer exists are revoked and reported; a
     * grantee whose type the morph map names is found, a soft-deleted grantee
     * keeps its grants, and a grantee type naming no model class is reported
     * and left while the types after it are still checked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokesTheGrantsOfGranteesThatAreGone(): void
    {
        Relation::morphMap(['stub_identity' => StubIdentity::class]);

        $role  = Role::create(['name' => 'editor']);
        $gone  = StubIdentity::create(['id' => 'user-gone']);
        $kept  = StubIdentity::create(['id' => 'user-kept']);
        $soft  = NumberedIdentity::create(['name' => 'Ada']);
        $other = NumberedIdentity::create(['name' => 'Grace']);

        $gone->assignRole($role);
        $kept->assignRole($role);
        $soft->assignRole($role);
        $other->assignRole($role);

        DB::table('stub_identities')->where('id', 'user-gone')->delete();
        DB::table('stub_numbered_identities')->where('id', $other->id)->delete();
        $soft->delete();

        DB::table('authorizable_roles')->insert(['role_id' => $role->id, 'authorizable_type' => 'ghost_type', 'authorizable_id' => '1']);

        Event::fake();

        $result = self::pruner()->prune(1000);

        self::assertSame(2, $result->orphaned);
        self::assertSame(['ghost_type'], $result->unresolvedTypes);
        self::assertEqualsCanonicalizing(['user-kept', (string) $soft->id, '1'], DB::table('authorizable_roles')->pluck('authorizable_id')->all());
        Event::assertDispatchedTimes(RoleRevoked::class, 2);
        Event::assertDispatched(
            RoleRevoked::class,
            static fn (RoleRevoked $event): bool => $event->grantee->id === 'user-gone' && $event->grantee->type === 'stub_identity' && $event->operation->actor === null,
        );
    }

    /**
     * The inline policies of a grantee that no longer exists are deleted and
     * reported, with their attachments, and pretending only counts them; those
     * of a grantee that exists or is soft-deleted stay, and an owner type
     * naming no model class is reported and left.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletesTheInlinePoliciesOfGranteesThatAreGone(): void
    {
        $gone    = StubIdentity::create(['id' => 'user-gone']);
        $goneToo = StubIdentity::create(['id' => 'user-gone-too']);
        $kept    = StubIdentity::create(['id' => 'user-kept']);
        $soft    = NumberedIdentity::create(['name' => 'Ada']);
        $role    = Role::create(['name' => 'editor']);

        $gone->attachPolicy($gone->createInlinePolicy('gone-first', ['version' => 1, 'statements' => []]));
        $gone->createInlinePolicy('gone-second', ['version' => 1, 'statements' => []]);
        $goneToo->createInlinePolicy('gone-too', ['version' => 1, 'statements' => []]);
        $kept->createInlinePolicy('kept', ['version' => 1, 'statements' => []]);
        $soft->createInlinePolicy('soft', ['version' => 1, 'statements' => []]);
        $role->createInlinePolicy('role', ['version' => 1, 'statements' => []]);
        Policy::create(['name' => 'ghost', 'document' => ['version' => 1, 'statements' => []], 'owner_type' => 'ghost_owner', 'owner_id' => '1']);
        Policy::create(['name' => 'managed', 'document' => ['version' => 1, 'statements' => []]]);

        DB::table('stub_identities')->whereIn('id', ['user-gone', 'user-gone-too'])->delete();
        $soft->delete();

        Event::fake([PolicyDeleted::class]);

        $pretended = self::pruner()->prune(1, true);

        self::assertSame(3, $pretended->inlinePolicies);
        self::assertSame(1, $pretended->orphaned);
        self::assertSame(['ghost_owner'], $pretended->unresolvedTypes);
        self::assertSame(8, Policy::query()->count());
        Event::assertNotDispatched(PolicyDeleted::class);

        $result = self::pruner()->prune(1);

        self::assertSame(3, $result->inlinePolicies);
        self::assertSame(1, $result->orphaned);
        self::assertSame(['ghost_owner'], $result->unresolvedTypes);
        self::assertSame(['ghost', 'kept', 'managed', 'role', 'soft'], Policy::query()->orderBy('name')->pluck('name')->all());
        self::assertSame(0, DB::table('authorizable_policies')->count());
        Event::assertDispatchedTimes(PolicyDeleted::class, 3);
    }

    /**
     * Pretending counts exactly what a real run removes: an expired grant of a
     * grantee that is gone once, among the expired, and the attachment of the
     * grantee's own inline policy among its orphaned grants.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPretendingCountsWhatARealRunRemoves(): void
    {
        $gone = StubIdentity::create(['id' => 'user-gone']);

        $gone->assignRole(Role::create(['name' => 'editor']), Carbon::parse('2026-07-01 11:00:00'));
        $gone->givePermission(Permission::create(['name' => 'posts:read']));
        $gone->attachPolicy($gone->createInlinePolicy('mine', ['version' => 1, 'statements' => []]));

        DB::table('stub_identities')->where('id', 'user-gone')->delete();

        Event::fake();

        $pretended = self::pruner()->prune(1000, true);
        $result    = self::pruner()->prune(1000);

        self::assertSame([1, 2, 1], [$pretended->expired, $pretended->orphaned, $pretended->inlinePolicies]);
        self::assertSame([$result->expired, $result->orphaned, $result->inlinePolicies], [$pretended->expired, $pretended->orphaned, $pretended->inlinePolicies]);
        self::assertSame(0, Policy::query()->count());
    }

    /**
     * The orphaned grants are revoked before any inline policy is deleted, so a
     * policy that cannot be deleted never keeps the grants of a grantee that is
     * gone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInlinePolicyThatCannotBeDeletedLeavesTheOrphanedGrantsRevoked(): void
    {
        $gone = StubIdentity::create(['id' => 'user-gone']);

        $gone->givePermission(Permission::create(['name' => 'posts:read']));

        // A row the observer would refuse, written past it.
        DB::table('policies')->insert([
            'id'         => '00000000-0000-0000-0000-000000000001',
            'name'       => 'stuck',
            'is_system'  => true,
            'document'   => '{"version":1,"statements":[]}',
            'owner_type' => $gone->getMorphClass(),
            'owner_id'   => 'user-gone',
        ]);

        DB::table('stub_identities')->where('id', 'user-gone')->delete();

        try {
            self::pruner()->prune(1000);
            self::fail('A system inline policy was deleted.');
        } catch (SystemPolicyProtectedException) {
            self::assertSame(0, DB::table('authorizable_permissions')->count());
            self::assertSame(1, Policy::query()->count());
        }
    }

    /**
     * The resource policy attachments of a record that no longer exists are
     * detached and reported, in every scope, and pretending only counts them;
     * those of a record that exists or is soft-deleted stay, a whole type's
     * attachments are never removed, and a resource type naming no model class
     * is reported and left.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDetachesTheResourcePoliciesOfRecordsThatAreGone(): void
    {
        Relation::morphMap(['stub_identity' => StubIdentity::class]);

        $tenant  = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'tenant-a']);
        $policy  = Policy::create(['name' => 'sharing', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']]]]]);
        $gone    = StubIdentity::create(['id' => 'record-gone']);
        $kept    = StubIdentity::create(['id' => 'record-kept']);
        $soft    = NumberedIdentity::create(['name' => 'Ada']);
        $service = ResourcePolicyService::instance();

        self::assertInstanceOf(ResourcePolicyService::class, $service);

        foreach ([$gone, $kept, $soft, StubIdentity::class, ['posts', 7]] as $resource) {
            $service->attach($policy, $resource);
        }

        $service->attach($policy, $gone, $tenant);

        DB::table('stub_identities')->where('id', 'record-gone')->delete();
        $soft->delete();

        Event::fake([ResourcePolicyDetached::class]);

        $pretended = self::pruner()->prune(1000, true);

        self::assertSame([2, ['posts']], [$pretended->resourcePolicies, $pretended->unresolvedResourceTypes]);
        self::assertSame(6, DB::table('resource_policies')->count());
        Event::assertNotDispatched(ResourcePolicyDetached::class);

        $result = self::pruner()->prune(1000);

        self::assertSame([2, ['posts']], [$result->resourcePolicies, $result->unresolvedResourceTypes]);
        self::assertSame([], $result->unresolvedTypes);
        self::assertEqualsCanonicalizing(['record-kept', (string) $soft->id, null, '7'], DB::table('resource_policies')->pluck('resource_id')->all());
        Event::assertDispatchedTimes(ResourcePolicyDetached::class, 2);
        Event::assertDispatched(
            ResourcePolicyDetached::class,
            static fn (ResourcePolicyDetached $event): bool => [$event->resourceType, $event->resourceId, $event->operation->actor] === ['stub_identity', 'record-gone', null],
        );
    }

    /**
     * The boundaries of a grantee that no longer exists, one whose only rows
     * are boundaries included, are removed and reported in every scope, and
     * counted apart from its grants, and pretending only counts them; a grantee
     * that exists keeps its boundary, a grantee type that names no model class
     * keeps its own and is reported, and the policy can be deleted once no
     * boundary uses it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovesTheBoundariesOfGranteesThatAreGone(): void
    {
        $tenant     = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'tenant-a']);
        $policy     = Policy::create(['name' => 'read-only', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);
        $kept       = Policy::create(['name' => 'kept-cap', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);
        $gone       = StubIdentity::create(['id' => 'user-gone']);
        $alive      = StubIdentity::create(['id' => 'user-kept']);
        $boundaries = BoundaryService::instance();

        self::assertInstanceOf(BoundaryService::class, $boundaries);

        $boundaries->set($gone, $policy);
        $boundaries->set($gone, $policy, $tenant);
        $boundaries->set($alive, $kept);
        $boundaries->set(new Reference('unmapped_type', '1'), $kept);
        $gone->assignRole(Role::create(['name' => 'editor']));

        DB::table('stub_identities')->where('id', 'user-gone')->delete();

        Event::fake([BoundaryRemoved::class]);

        $pretended = self::pruner()->prune(1000, true);

        self::assertSame([1, 2, ['unmapped_type']], [$pretended->orphaned, $pretended->boundaries, $pretended->unresolvedTypes]);
        self::assertSame(4, DB::table('authorizable_boundaries')->count());
        Event::assertNotDispatched(BoundaryRemoved::class);

        $result = self::pruner()->prune(1000);

        self::assertSame([1, 2, ['unmapped_type']], [$result->orphaned, $result->boundaries, $result->unresolvedTypes]);
        self::assertSame(['1', 'user-kept'], DB::table('authorizable_boundaries')->orderBy('authorizable_id')->pluck('authorizable_id')->all());
        Event::assertDispatchedTimes(BoundaryRemoved::class, 2);
        Event::assertDispatched(
            BoundaryRemoved::class,
            static fn (BoundaryRemoved $event): bool => [$event->grantee->id, $event->name, $event->operation->actor] === ['user-gone', 'read-only', null],
        );

        self::assertTrue((bool) $policy->delete());
    }

    /**
     * Once the package refuses, pruning refuses by its own guard, pretending or
     * not, before it reads or deletes anything.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPruningRefusesOnceThePackageRefuses(): void
    {
        $pruner = $this->container()->make(GrantPruner::class);

        $this->refuseThePackage();

        $this->assertEachRefused([
            'prune'            => static fn () => $pruner->prune(100),
            'prune pretending' => static fn () => $pruner->prune(100, true),
        ]);
    }

    /**
     * Return the grant pruner the container builds.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantPruner
     */
    private static function pruner(): GrantPruner
    {
        return app(GrantPruner::class);
    }
}
