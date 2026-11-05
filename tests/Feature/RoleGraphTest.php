<?php

declare(strict_types = 1);

namespace Tests\Feature;

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
     * Permissions another tenant owns are not held through a shared role.
     *
     * @return void
     */
    public function testPermissionsFollowTheTenantScope(): void
    {
        $tenant = self::createTenant('t-2');
        $role   = Role::create(['name' => 'shared', 'guard' => 'web']);

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

        self::assertEqualsCanonicalizing(['posts:read', 'posts:edit'], RoleGraph::permissionNamesWithin($reach, [$leaf->id, $missing]));
        self::assertSame([], RoleGraph::permissionNamesWithin(RoleGraph::reach([$other->id]), [$other->id]));

        config(['authorization.hierarchy.enabled' => false]);

        self::assertSame(['posts:edit'], RoleGraph::permissionNamesWithin(RoleGraph::reach([$leaf->id]), [$leaf->id]));
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

        self::assertNull(RoleGraph::permissionNamesWithin($reach, [$leaf->id]));

        DB::table('roles')->where('id', $leaf->id)->update(['parent_id' => $root->id]);
        DB::table('roles')->where('id', $root->id)->update(['parent_id' => null]);

        self::assertSame([], RoleGraph::permissionNamesWithin($reach, [$leaf->id]));

        config(['authorization.hierarchy.enabled' => false]);
        DB::table('roles')->where('id', $leaf->id)->update(['parent_id' => $elsewhere->id]);

        self::assertSame([], RoleGraph::permissionNamesWithin(RoleGraph::reach([$leaf->id]), [$leaf->id]));
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
