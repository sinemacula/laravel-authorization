<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use SineMacula\Laravel\Authorization\Resolvers\NullTenantResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use SineMacula\Laravel\Authorization\Traits\HasRoleHierarchy;
use SineMacula\Laravel\Authorization\Traits\ManagesPermissions;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for role hierarchy / inheritance.
 *
 * Validates the parent-child tree on the Role model, permission
 * inheritance through ancestors, cycle detection on save, and the
 * hierarchy-enabled config toggle.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Role::class)]
#[CoversClass(RoleObserver::class)]
#[CoversClass(RoleHierarchyCycleException::class)]
#[CoversClass(TenantScope::class)]
#[CoversClass(NullTenantResolver::class)]
#[CoversClass(ResolutionCacheContext::class)]
#[CoversClass(InvalidTenantException::class)]
#[CoversClass(InvalidTenantColumnsException::class)]
#[CoversClass(GuardScopedLookup::class)]
#[CoversTrait(HasRoleHierarchy::class)]
#[CoversTrait(ManagesPermissions::class)]
final class RoleHierarchyTest extends TestCase
{
    /**
     * A child role inherits its parent's permissions via
     * `getPermissions()`.
     *
     * @return void
     */
    public function testChildInheritsParentPermissions(): void
    {
        $parent = $this->makeRole('admin');
        $child  = $this->makeRole('editor', parentId: $parent->getKey());

        $this->makePermission('posts:create');
        $this->makePermission('posts:delete');

        $parent->givePermission('posts:delete');
        $child->givePermission('posts:create');

        $permissions = $child->fresh()->getPermissions(); // @phpstan-ignore method.nonObject
        \sort($permissions);

        self::assertSame(['posts:create', 'posts:delete'], $permissions);
    }

    /**
     * A grandchild inherits through two levels.
     *
     * @return void
     */
    public function testGrandchildInheritsThroughTwoLevels(): void
    {
        $root   = $this->makeRole('admin');
        $middle = $this->makeRole('editor', parentId: $root->getKey());
        $leaf   = $this->makeRole('viewer', parentId: $middle->getKey());

        $this->makePermission('posts:create');
        $this->makePermission('posts:edit');
        $this->makePermission('posts:view');

        $root->givePermission('posts:create');
        $middle->givePermission('posts:edit');
        $leaf->givePermission('posts:view');

        $permissions = $leaf->fresh()->getPermissions(); // @phpstan-ignore method.nonObject
        \sort($permissions);

        self::assertSame(['posts:create', 'posts:edit', 'posts:view'], $permissions);
    }

    /**
     * Direct permissions on a child are unioned with inherited ones
     * (no duplicates).
     *
     * @return void
     */
    public function testDirectPermissionsUnionedWithInheritedNoDuplicates(): void
    {
        $parent = $this->makeRole('admin');
        $child  = $this->makeRole('editor', parentId: $parent->getKey());

        $perm = $this->makePermission('posts:create');

        $parent->givePermission($perm);
        $child->givePermission($perm);

        $permissions = $child->fresh()->getPermissions(); // @phpstan-ignore method.nonObject

        self::assertSame(['posts:create'], $permissions);
    }

    /**
     * Setting a parent that would create a cycle throws
     * RoleHierarchyCycleException.
     *
     * @return void
     */
    public function testCycleDetectionOnParentAssignment(): void
    {
        $parent = $this->makeRole('admin');
        $child  = $this->makeRole('editor', parentId: $parent->getKey());

        $this->expectException(RoleHierarchyCycleException::class);

        $parent->parent_id = $child->getKey(); // @phpstan-ignore assign.propertyType
        $parent->save();
    }

    /**
     * A self-referential parent (role is its own parent) throws the
     * cycle exception.
     *
     * @return void
     */
    public function testSelfReferentialParentThrowsCycleException(): void
    {
        $role = $this->makeRole('admin');

        $this->expectException(RoleHierarchyCycleException::class);

        $role->parent_id = $role->getKey(); // @phpstan-ignore assign.propertyType
        $role->save();
    }

    /**
     * Removing a parent (`parent_id = null`) works and stops
     * inheritance.
     *
     * @return void
     */
    public function testRemovingParentStopsInheritance(): void
    {
        $parent = $this->makeRole('admin');
        $child  = $this->makeRole('editor', parentId: $parent->getKey());

        $this->makePermission('posts:delete');
        $this->makePermission('posts:create');

        $parent->givePermission('posts:delete');
        $child->givePermission('posts:create');

        // Verify inheritance first.
        $child = $child->fresh(); // @phpstan-ignore assign.propertyType
        self::assertTrue(\in_array('posts:delete', $child->getPermissions(), true)); // @phpstan-ignore method.nonObject

        // Remove parent.
        $child->parent_id = null; // @phpstan-ignore property.nonObject
        $child->save(); // @phpstan-ignore method.nonObject

        $child = $child->fresh(); // @phpstan-ignore assign.propertyType, method.nonObject
        self::assertSame(['posts:create'], $child->getPermissions()); // @phpstan-ignore method.nonObject
    }

    /**
     * An identity holding a child role can `hasPermission()` for an
     * ancestor-inherited permission.
     *
     * @return void
     */
    public function testIdentityWithChildRoleInheritsAncestorPermission(): void
    {
        $parent = $this->makeRole('admin');
        $child  = $this->makeRole('editor', parentId: $parent->getKey());

        $this->makePermission('posts:delete');
        $parent->givePermission('posts:delete');

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole('editor');

        self::assertTrue($user->hasPermission('posts:delete'));
    }

    /**
     * With `hierarchy.enabled = false`, `getPermissions()` returns
     * only direct permissions even when parent is set.
     *
     * @return void
     */
    public function testHierarchyDisabledReturnsOnlyDirectPermissions(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.hierarchy.enabled', false);

        $parent = $this->makeRole('admin');
        $child  = $this->makeRole('editor', parentId: $parent->getKey());

        $this->makePermission('posts:delete');
        $this->makePermission('posts:create');

        $parent->givePermission('posts:delete');
        $child->givePermission('posts:create');

        self::assertSame(['posts:create'], $child->fresh()->getPermissions()); // @phpstan-ignore method.nonObject
    }

    /**
     * `ancestors()` returns the chain in root-first order.
     *
     * @return void
     */
    public function testAncestorsReturnsRootFirstOrder(): void
    {
        $root   = $this->makeRole('admin');
        $middle = $this->makeRole('editor', parentId: $root->getKey());
        $leaf   = $this->makeRole('viewer', parentId: $middle->getKey());

        $ancestors = $leaf->ancestors();

        self::assertCount(2, $ancestors);
        self::assertTrue($ancestors->first()->is($root)); // @phpstan-ignore method.nonObject
        self::assertTrue($ancestors->last()->is($middle)); // @phpstan-ignore method.nonObject
    }

    /**
     * `descendants()` returns the subtree.
     *
     * @return void
     */
    public function testDescendantsReturnsSubtree(): void
    {
        $root   = $this->makeRole('admin');
        $middle = $this->makeRole('editor', parentId: $root->getKey());
        $leaf   = $this->makeRole('viewer', parentId: $middle->getKey());

        $descendants = $root->descendants();

        self::assertCount(2, $descendants);

        $ids = $descendants->map(fn (Role $r): string => (string) $r->getKey())->all(); // @phpstan-ignore cast.string

        self::assertContains((string) $middle->getKey(), $ids); // @phpstan-ignore cast.string
        self::assertContains((string) $leaf->getKey(), $ids); // @phpstan-ignore cast.string
    }

    /**
     * `isAncestorOf()` / `isDescendantOf()` return correct booleans.
     *
     * @return void
     */
    public function testIsAncestorOfAndIsDescendantOf(): void
    {
        $root  = $this->makeRole('admin');
        $child = $this->makeRole('editor', parentId: $root->getKey());
        $leaf  = $this->makeRole('viewer', parentId: $child->getKey());

        self::assertTrue($root->isAncestorOf($child));
        self::assertTrue($root->isAncestorOf($leaf));
        self::assertFalse($child->isAncestorOf($root));
        self::assertFalse($leaf->isAncestorOf($root));

        self::assertTrue($leaf->isDescendantOf($root));
        self::assertTrue($child->isDescendantOf($root));
        self::assertFalse($root->isDescendantOf($leaf));
    }

    /**
     * Cycle detection in `ancestors()` carries the proposed parent's
     * name — not its UUID — so caught-exception output is readable
     * (issue #100).
     *
     * @return void
     */
    public function testAncestorsCycleExceptionCarriesRoleNames(): void
    {
        $root  = $this->makeRole('admin');
        $child = $this->makeRole('editor', parentId: $root->getKey());

        $rootId  = (string) $root->getKey(); // @phpstan-ignore cast.string
        $childId = (string) $child->getKey(); // @phpstan-ignore cast.string

        // Bypass the saving hook to inject a cycle: point root's
        // parent at the child so `ancestors()` on child loops.
        $updated = DB::table('roles')->where('id', $rootId)->update(['parent_id' => $childId]);
        self::assertSame(1, $updated, 'Cycle-injection update should hit one row.');

        try {
            $child->fresh()->ancestors(); // @phpstan-ignore method.nonObject
            self::fail('RoleHierarchyCycleException was not thrown.');
        } catch (RoleHierarchyCycleException $exception) {
            self::assertSame('editor', $exception->getRoleName());
            // The proposed-parent is whatever the walk re-encounters
            // as it closes the loop — it is the role's *name*, not
            // its UUID (the #100 regression guard).
            self::assertSame('admin', $exception->getProposedParentName());
            self::assertStringNotContainsString($rootId, $exception->getMessage());
            self::assertStringNotContainsString($childId, $exception->getMessage());
            self::assertStringContainsString('admin', $exception->getMessage());
            self::assertStringContainsString('editor', $exception->getMessage());
        }
    }

    /**
     * `descendants()` terminates safely (no infinite loop) when a
     * cycle has been injected directly into the database, bypassing
     * the Eloquent saving-hook guard (issue #101).
     *
     * @return void
     */
    public function testDescendantsTerminatesOnDatabaseLevelCycle(): void
    {
        $root  = $this->makeRole('admin');
        $child = $this->makeRole('editor', parentId: $root->getKey());

        // Inject a cycle bypassing the saving hook: point root's
        // parent at its own child.
        DB::table('roles')->where('id', (string) $root->getKey()) // @phpstan-ignore cast.string
            ->update(['parent_id' => (string) $child->getKey()]); // @phpstan-ignore cast.string

        $this->expectException(RoleHierarchyCycleException::class);

        $root->fresh()->descendants(); // @phpstan-ignore method.nonObject
    }

    /**
     * `isAncestorOf()` terminates safely on a database-level cycle
     * (issue #102) — guarded by the `ancestors()` walk's cycle set.
     *
     * @return void
     */
    public function testIsAncestorOfTerminatesOnDatabaseLevelCycle(): void
    {
        $root  = $this->makeRole('admin');
        $child = $this->makeRole('editor', parentId: $root->getKey());

        // Inject a cycle: point root's parent at its own child so
        // that walking the child's ancestor chain loops.
        DB::table('roles')->where('id', (string) $root->getKey()) // @phpstan-ignore cast.string
            ->update(['parent_id' => (string) $child->getKey()]); // @phpstan-ignore cast.string

        $this->expectException(RoleHierarchyCycleException::class);

        $root->fresh()->isAncestorOf($child->fresh()); // @phpstan-ignore method.nonObject
    }

    /**
     * Build a web-guarded role with the given name and optional parent.
     *
     * @param  string  $name
     * @param  string|null  $parentId
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private function makeRole(string $name, ?string $parentId = null): Role
    {
        return Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => $name,
            'guard_name' => 'web',
            'parent_id'  => $parentId,
        ]);
    }

    /**
     * Build a web-guarded permission with the given name.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private function makePermission(string $name): Permission
    {
        return Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => $name,
            'guard_name' => 'web',
        ]);
    }
}
