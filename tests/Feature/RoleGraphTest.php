<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\RoleGraph;
use Tests\Concerns\ActsAsTenant;
use Tests\TestCase;

/**
 * Feature tests for reading the role hierarchy and the permissions roles hold
 * in a fixed number of queries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RoleGraph::class)]
final class RoleGraphTest extends TestCase
{
    use ActsAsTenant;

    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Each role's chain runs from the root down to its immediate parent, and a
     * root role has none.
     *
     * @return void
     */
    public function testChainsRunFromTheRootDown(): void
    {
        [$root, $middle, $leaf] = self::chainOf(3, 'a');
        $other                  = Role::create(['name' => 'other', 'guard' => 'web', 'parent_id' => $middle->id]);

        $chains = RoleGraph::ancestorsOf([$root, $leaf, $other]);

        self::assertSame([$root->id, $middle->id], self::ids($chains[$leaf->id]));
        self::assertSame([$root->id, $middle->id], self::ids($chains[$other->id]));
        self::assertSame([], $chains[$root->id]);
    }

    /**
     * The ancestors of any number of roles, however deep, take two queries, and
     * roles without a parent take none.
     *
     * @return void
     */
    public function testAncestorsTakeTwoQueriesWhateverTheDepth(): void
    {
        $shallow = self::chainOf(2, 'shallow')[1];
        $deep    = [self::chainOf(6, 'deep')[5], self::chainOf(5, 'deeper')[4], self::chainOf(4, 'deepest')[3]];
        $root    = Role::create(['name' => 'root', 'guard' => 'web']);

        self::assertSame(2, self::queriesFor(static fn (): array => RoleGraph::ancestorsOf([$shallow])));
        self::assertSame(2, self::queriesFor(static fn (): array => RoleGraph::ancestorsOf($deep)));
        self::assertSame(0, self::queriesFor(static fn (): array => RoleGraph::ancestorsOf([$root])));
    }

    /**
     * A parent the tenant scope hides ends the chain there, as a missing parent
     * does.
     *
     * @return void
     */
    public function testAHiddenParentEndsTheChain(): void
    {
        $tenant = self::createTenant('t-1');

        $this->actAsTenant($tenant);

        $parent = Role::create(['name' => 'owner', 'guard' => 'web', ...self::ownedBy($tenant)]);
        $child  = Role::create(['name' => 'member', 'guard' => 'web', 'parent_id' => $parent->id, ...self::ownedBy($tenant)]);

        self::assertSame([$parent->id], self::ids(RoleGraph::ancestorsOf([$child])[$child->id]));

        $this->actAsTenant(null);

        self::assertSame([], RoleGraph::ancestorsOf([$child])[$child->id]);
    }

    /**
     * A stored cycle is refused with the role's name and the parent that closes
     * it, rather than walked forever.
     *
     * @return void
     */
    public function testACycleIsRefused(): void
    {
        [$root, $child] = self::chainOf(2, 'loop');

        DB::table('roles')->where('id', $root->id)->update(['parent_id' => $child->id]);

        try {
            RoleGraph::ancestorsOf([$child]);
            self::fail('RoleHierarchyCycleException was not thrown.');
        } catch (RoleHierarchyCycleException $exception) {
            self::assertSame('loop-1', $exception->getRoleName());
            self::assertSame('loop-0', $exception->getProposedParentName());
        }
    }

    /**
     * Roles hold their own permissions and their ancestors', each permission
     * once however many of the roles hold it, read in one query after the
     * hierarchy's two.
     *
     * @return void
     */
    public function testPermissionsIncludeTheAncestorsOnce(): void
    {
        [$root, $leaf] = self::chainOf(2, 'p');
        $sibling       = Role::create(['name' => 'sibling', 'guard' => 'web', 'parent_id' => $root->id]);

        $read = Permission::create(['name' => 'posts:read', 'guard' => 'web']);

        $root->permissions()->attach($read->id);
        $leaf->permissions()->attach(Permission::create(['name' => 'posts:edit', 'guard' => 'web'])->id);
        $sibling->permissions()->attach([$read->id, Permission::create(['name' => 'posts:delete', 'guard' => 'web'])->id]);

        $names = null;

        self::assertSame(3, self::queriesFor(static function () use ($leaf, $sibling, &$names): void {
            $names = RoleGraph::permissionNamesHeldBy([$leaf, $sibling]);
        }));
        self::assertEqualsCanonicalizing(['posts:read', 'posts:edit', 'posts:delete'], $names);
    }

    /**
     * A hierarchy flag that is not configured leaves the hierarchy on.
     *
     * @return void
     */
    public function testTheHierarchyIsOnUnlessDisabled(): void
    {
        config(['authorization.hierarchy' => []]);

        [$root, $leaf] = self::chainOf(2, 'default');

        $root->permissions()->attach(Permission::create(['name' => 'posts:read', 'guard' => 'web'])->id);

        self::assertSame(['posts:read'], RoleGraph::permissionNamesHeldBy([$leaf]));
    }

    /**
     * With the hierarchy disabled a role holds only its own permissions, and
     * the hierarchy is not read.
     *
     * @return void
     */
    public function testWithoutTheHierarchyOnlyOwnPermissionsCount(): void
    {
        config(['authorization.hierarchy.enabled' => false]);

        [$root, $leaf] = self::chainOf(2, 'flat');

        $root->permissions()->attach(Permission::create(['name' => 'posts:read', 'guard' => 'web'])->id);
        $leaf->permissions()->attach(Permission::create(['name' => 'posts:edit', 'guard' => 'web'])->id);

        $names = null;

        self::assertSame(1, self::queriesFor(static function () use ($leaf, &$names): void {
            $names = RoleGraph::permissionNamesHeldBy([$leaf]);
        }));
        self::assertSame(['posts:edit'], $names);
    }

    /**
     * No roles hold no permissions, without a query.
     *
     * @return void
     */
    public function testNoRolesHoldNothing(): void
    {
        self::assertSame(0, self::queriesFor(static fn (): array => RoleGraph::permissionNamesHeldBy([])));
        self::assertSame([], RoleGraph::permissionNamesHeldBy([]));
    }

    /**
     * A role's grant of a permission counts until its expiry, its own or an
     * ancestor's, and the nearest expiry still ahead is reported.
     *
     * @return void
     */
    public function testAnExpiredPermissionIsNotHeldAndTheNearestExpiryIsReported(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        $parent = Role::create(['name' => 'reader']);
        $role   = Role::create(['name' => 'editor', 'parent_id' => $parent->id]);

        $role->givePermission(Permission::create(['name' => 'posts:edit']), Carbon::parse('2026-07-01 12:10:00'));
        $role->givePermission(Permission::create(['name' => 'posts:list']));
        $role->givePermission(Permission::create(['name' => 'posts:delete']), Carbon::parse('2026-07-01 11:00:00'));
        $parent->givePermission(Permission::create(['name' => 'posts:read']), Carbon::parse('2026-07-01 12:05:00'));

        $held   = RoleGraph::permissionsHeldBy([$role]);
        $within = RoleGraph::permissionsWithin(RoleGraph::reach([$role->id]), [$role->id]);

        self::assertEqualsCanonicalizing(['posts:edit', 'posts:list', 'posts:read'], $held->names);
        self::assertSame(300, $held->expiresIn);
        self::assertEqualsCanonicalizing(['posts:edit', 'posts:list', 'posts:read'], $within?->names);
        self::assertSame(300, $within?->expiresIn);

        Carbon::setTestNow('2026-07-01 12:05:00');

        self::assertEqualsCanonicalizing(['posts:edit', 'posts:list'], RoleGraph::permissionNamesHeldBy([$role]));
        self::assertSame(300, RoleGraph::permissionsHeldBy([$role])->expiresIn);
        self::assertNull(RoleGraph::permissionsHeldBy([$parent])->expiresIn);
        self::assertNull(RoleGraph::permissionsHeldBy([])->expiresIn);
    }

    /**
     * A tenant's own permissions held through its role count only in that
     * tenant; the platform's count everywhere.
     *
     * @return void
     */
    public function testPermissionsFollowTheTenantScope(): void
    {
        $tenant = self::createTenant('t-2');
        $role   = Role::query()->withoutGlobalScope(TenantScope::class)->create(['name' => 'shared', 'guard' => 'web', ...self::ownedBy($tenant)]);

        $role->permissions()->attach(Permission::create(['name' => 'posts:read', 'guard' => 'web'])->id);
        $role->permissions()->attach(Permission::query()->withoutGlobalScope(TenantScope::class)->create(['name' => 'posts:own', 'guard' => 'web', ...self::ownedBy($tenant)])->id);

        self::assertSame(['posts:read'], RoleGraph::permissionNamesHeldBy([$role]));

        $this->actAsTenant($tenant);

        self::assertEqualsCanonicalizing(['posts:read', 'posts:own'], RoleGraph::permissionNamesHeldBy([$role]));
    }

    /**
     * The reach of roles is each of them and every role above them, with its
     * parent, in one query; with the hierarchy disabled it is only the roles,
     * without one.
     *
     * @return void
     */
    public function testReachRunsUpTheHierarchy(): void
    {
        [$root, $middle, $leaf] = self::chainOf(3, 'r');

        $reach = RoleGraph::reach([$leaf->id]);

        self::assertSame(1, self::queriesFor(static fn (): array => RoleGraph::reach([$leaf->id])));
        self::assertEqualsCanonicalizing([$leaf->id, $middle->id, $root->id], \array_keys($reach));
        self::assertSame($middle->id, $reach[$leaf->id]);
        self::assertSame($root->id, $reach[$middle->id]);
        self::assertArrayHasKey($root->id, $reach);
        self::assertNull($reach[$root->id]);
        self::assertSame([], RoleGraph::reach([]));

        config(['authorization.hierarchy.enabled' => false]);

        self::assertSame(0, self::queriesFor(static fn (): array => RoleGraph::reach([$leaf->id])));
        self::assertSame([$leaf->id => null], RoleGraph::reach([$leaf->id]));
    }

    /**
     * Within the reach read, the held roles hold their own permissions and
     * their ancestors'; a held role the tenant scope hides holds none.
     *
     * @return void
     */
    public function testPermissionsWithinTheReach(): void
    {
        [$root, $leaf] = self::chainOf(2, 'w');
        $other         = Role::create(['name' => 'other', 'guard' => 'web']);

        $root->permissions()->attach(Permission::create(['name' => 'posts:read', 'guard' => 'web'])->id);
        $leaf->permissions()->attach(Permission::create(['name' => 'posts:edit', 'guard' => 'web'])->id);

        $missing = (string) Str::uuid();
        $reach   = RoleGraph::reach([$leaf->id, $missing]);

        self::assertEqualsCanonicalizing(['posts:read', 'posts:edit'], RoleGraph::permissionsWithin($reach, [$leaf->id, $missing])?->names);
        self::assertSame([], RoleGraph::permissionsWithin(RoleGraph::reach([$other->id]), [$other->id])?->names);

        config(['authorization.hierarchy.enabled' => false]);

        self::assertSame(['posts:edit'], RoleGraph::permissionsWithin(RoleGraph::reach([$leaf->id]), [$leaf->id])?->names);
    }

    /**
     * A role whose parent is now one the reach did not read means the hierarchy
     * moved after it was read, so nothing is returned.
     *
     * @return void
     */
    public function testAMovedHierarchyIsReported(): void
    {
        [$root, $leaf] = self::chainOf(2, 'm');
        $elsewhere     = Role::create(['name' => 'elsewhere', 'guard' => 'web']);

        $reach = RoleGraph::reach([$leaf->id]);

        DB::table('roles')->where('id', $leaf->id)->update(['parent_id' => $elsewhere->id]);

        $moved = RoleGraph::permissionsWithin($reach, [$leaf->id]);

        self::assertNull($moved);

        DB::table('roles')->where('id', $leaf->id)->update(['parent_id' => $root->id]);
        DB::table('roles')->where('id', $root->id)->update(['parent_id' => null]);

        $within = RoleGraph::permissionsWithin($reach, [$leaf->id]);

        self::assertNotNull($within);
        self::assertSame([], $within->names);

        config(['authorization.hierarchy.enabled' => false]);
        DB::table('roles')->where('id', $leaf->id)->update(['parent_id' => $elsewhere->id]);

        self::assertSame([], RoleGraph::permissionsWithin(RoleGraph::reach([$leaf->id]), [$leaf->id])?->names);
    }

    /**
     * The keys a holder of the roles gets grants through are the roles' own and
     * their ancestors', root first, ancestors only while the hierarchy is
     * enabled.
     *
     * @return void
     */
    public function testTheKeysHeldByTheRolesRunUpTheHierarchy(): void
    {
        [$root, $middle, $leaf] = self::chainOf(3, 'k');
        $other                  = Role::create(['name' => 'other', 'guard' => 'web']);

        self::assertSame([$leaf->id, $other->id, $root->id, $middle->id], RoleGraph::keysHeldBy([$leaf, $other]));
        self::assertSame([], RoleGraph::keysHeldBy([]));

        config(['authorization.hierarchy.enabled' => false]);

        self::assertSame([$leaf->id, $other->id], RoleGraph::keysHeldBy([$leaf, $other]));
    }

    /**
     * Within the reach read, the keys are the held roles the tenant scope shows
     * and their ancestors'; none when the hierarchy moved after it was read.
     *
     * @return void
     */
    public function testTheKeysWithinTheReach(): void
    {
        [$root, $leaf] = self::chainOf(2, 'r');
        $elsewhere     = Role::create(['name' => 'elsewhere', 'guard' => 'web']);
        $missing       = (string) Str::uuid();
        $reach         = RoleGraph::reach([$leaf->id, $missing]);

        self::assertSame([$leaf->id, $root->id], RoleGraph::keysWithin($reach, [$leaf->id, $missing]));
        self::assertSame([], RoleGraph::keysWithin([], []));

        DB::table('roles')->where('id', $leaf->id)->update(['parent_id' => $elsewhere->id]);

        self::assertNull(RoleGraph::keysWithin($reach, [$leaf->id]));

        config(['authorization.hierarchy.enabled' => false]);

        self::assertSame([$leaf->id], RoleGraph::keysWithin(RoleGraph::reach([$leaf->id]), [$leaf->id]));
    }

    /**
     * The path of each role is the role, then each ancestor from its parent up
     * to the root; with the hierarchy disabled, the role alone.
     *
     * @return void
     */
    public function testThePathsRunFromTheRoleUp(): void
    {
        $root   = Role::create(['name' => 'root']);
        $parent = Role::create(['name' => 'parent', 'parent_id' => $root->id]);
        $child  = Role::create(['name' => 'child', 'parent_id' => $parent->id]);
        $alone  = Role::create(['name' => 'alone']);
        $names  = static fn (array $paths): array => \array_map(static fn (array $path): array => \array_map(static fn (Role $role): string => $role->name, $path), $paths);

        self::assertSame([$child->id => ['child', 'parent', 'root'], $alone->id => ['alone']], $names(RoleGraph::pathsOf([$child, $alone])));
        self::assertSame([], RoleGraph::pathsOf([]));

        config(['authorization.hierarchy.enabled' => false]);

        self::assertSame([$child->id => ['child']], $names(RoleGraph::pathsOf([$child])));
    }

    /**
     * The chain of each role is its key, then each ancestor's from its parent
     * up to the root, as the paths run; with the hierarchy disabled, the role's
     * alone.
     *
     * @return void
     */
    public function testTheChainsRunFromTheRoleUp(): void
    {
        $root   = Role::create(['name' => 'root']);
        $parent = Role::create(['name' => 'parent', 'parent_id' => $root->id]);
        $child  = Role::create(['name' => 'child', 'parent_id' => $parent->id]);
        $alone  = Role::create(['name' => 'alone']);

        self::assertSame([$child->id => [$child->id, $parent->id, $root->id], $alone->id => [$alone->id]], RoleGraph::chainsOf([$child, $alone]));
        self::assertSame([], RoleGraph::chainsOf([]));

        config(['authorization.hierarchy.enabled' => false]);

        self::assertSame([$child->id => [$child->id]], RoleGraph::chainsOf([$child]));
    }

    /**
     * The permissions each role carries are read in one query, keyed by the
     * role, a grant that has expired left out; no role reads nothing.
     *
     * @return void
     */
    public function testThePermissionsEachRoleCarries(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        $editor = Role::create(['name' => 'editor']);
        $reader = Role::create(['name' => 'reader']);
        $empty  = Role::create(['name' => 'empty']);
        $read   = Permission::create(['name' => 'posts:read']);

        $editor->givePermission(Permission::create(['name' => 'posts:edit']));
        $editor->givePermission($read);
        $editor->givePermission(Permission::create(['name' => 'posts:delete']), Carbon::parse('2026-07-01 11:00:00'));
        $reader->givePermission($read);

        DB::enableQueryLog();
        DB::flushQueryLog();

        $carried = RoleGraph::permissionsByRole([$editor->id, $reader->id, $empty->id]);

        self::assertCount(1, DB::getQueryLog());

        DB::flushQueryLog();

        self::assertSame([], RoleGraph::permissionsByRole([]));
        self::assertSame([], DB::getQueryLog());
        self::assertEqualsCanonicalizing([$editor->id, $reader->id], \array_keys($carried));
        self::assertEqualsCanonicalizing(['posts:edit', 'posts:read'], $carried[$editor->id]);
        self::assertSame(['posts:read'], $carried[$reader->id]);
    }

    /**
     * Within the reach read, the chain of each held role the tenant scope shows
     * runs from the role up to the root, the role alone with the hierarchy
     * disabled; none when the hierarchy moved after it was read. Its keys list
     * each role then its ancestors from the root down, as the keys within the
     * reach do.
     *
     * @return void
     */
    public function testTheChainsWithinTheReach(): void
    {
        [$root, $middle, $leaf] = self::chainOf(3, 'c');
        $other                  = Role::create(['name' => 'other', 'guard' => 'web']);
        $elsewhere              = Role::create(['name' => 'elsewhere', 'guard' => 'web']);
        $missing                = (string) Str::uuid();
        $reach                  = RoleGraph::reach([$leaf->id, $other->id, $missing]);
        $chains                 = RoleGraph::chainsWithin($reach, [$leaf->id, $other->id, $missing]);

        self::assertSame([$leaf->id => [$leaf->id, $middle->id, $root->id], $other->id => [$other->id]], $chains);
        self::assertNotNull($chains);
        self::assertSame(RoleGraph::keysWithin($reach, [$leaf->id, $other->id, $missing]), RoleGraph::keysOf($chains));
        self::assertSame([$leaf->id, $root->id, $middle->id, $other->id], RoleGraph::keysOf($chains));

        DB::table('roles')->where('id', $root->id)->update(['parent_id' => $elsewhere->id]);

        self::assertNull(RoleGraph::chainsWithin($reach, [$leaf->id]));

        config(['authorization.hierarchy.enabled' => false]);

        self::assertSame([$leaf->id => [$leaf->id]], RoleGraph::chainsWithin(RoleGraph::reach([$leaf->id]), [$leaf->id]));
    }

    /**
     * The permissions the roles of the chains carry are read in the one query
     * the names take, with the key and name of each by the role carrying it,
     * each once; no role reads nothing.
     *
     * @return void
     */
    public function testThePermissionsCarriedWithinTheChains(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        [$root, $leaf] = self::chainOf(2, 'p');
        $read          = Permission::create(['name' => 'posts:read', 'guard' => 'web']);
        $edit          = Permission::create(['name' => 'posts:edit', 'guard' => 'web']);

        $root->givePermission($read, Carbon::parse('2026-07-01 13:00:00'));
        $leaf->givePermission($read);
        $leaf->givePermission($edit);

        $chains  = [$leaf->id => [$leaf->id, $root->id]];
        $carried = null;

        self::assertSame(1, self::queriesFor(static function () use ($chains, &$carried): void {
            $carried = RoleGraph::carriedWithin($chains);
        }));

        self::assertNotNull($carried);
        self::assertEqualsCanonicalizing(['posts:read', 'posts:edit'], $carried->names);
        self::assertSame(3600, $carried->expiresIn);
        self::assertSame([['id' => $read->id, 'name' => 'posts:read']], $carried->byRole[$root->id] ?? null);
        self::assertEqualsCanonicalizing([['id' => $read->id, 'name' => 'posts:read'], ['id' => $edit->id, 'name' => 'posts:edit']], $carried->byRole[$leaf->id] ?? null);
        self::assertSame([], RoleGraph::carriedWithin([])->byRole);
        self::assertNull(RoleGraph::permissionsWithin(RoleGraph::reach([$leaf->id]), [$leaf->id])?->byRole);
    }

    /**
     * Create a chain of roles, root first, each the parent of the next.
     *
     * @param  int  $length
     * @param  string  $prefix
     * @return list<\SineMacula\Laravel\Authorization\Models\Role>
     */
    private static function chainOf(int $length, string $prefix): array
    {
        $chain  = [];
        $parent = null;

        for ($i = 0; $i < $length; $i++) {
            $parent  = Role::create(['name' => "{$prefix}-{$i}", 'guard' => 'web', 'parent_id' => $parent?->id]);
            $chain[] = $parent;
        }

        return $chain;
    }

    /**
     * Return the keys of the roles, in order.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Models\Role>  $roles
     * @return list<string>
     */
    private static function ids(array $roles): array
    {
        return \array_map(static fn (Role $role): string => $role->id, $roles);
    }

    /**
     * Count the queries the work runs.
     *
     * @param  \Closure(): mixed  $work
     * @return int
     */
    private static function queriesFor(\Closure $work): int
    {
        DB::flushQueryLog();
        DB::enableQueryLog();

        $work();

        $count = \count(DB::getQueryLog());

        DB::disableQueryLog();

        return $count;
    }
}
