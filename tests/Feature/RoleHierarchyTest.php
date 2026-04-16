<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
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
#[CoversClass(RoleHierarchyCycleException::class)]
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

        $permissions = $child->fresh()->getPermissions();
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

        $permissions = $leaf->fresh()->getPermissions();
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

        $permissions = $child->fresh()->getPermissions();

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

        $parent->parent_id = $child->getKey();
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

        $role->parent_id = $role->getKey();
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
        $child = $child->fresh();
        self::assertTrue(\in_array('posts:delete', $child->getPermissions(), true));

        // Remove parent.
        $child->parent_id = null;
        $child->save();

        $child = $child->fresh();
        self::assertSame(['posts:create'], $child->getPermissions());
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
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.hierarchy.enabled', false);

        $parent = $this->makeRole('admin');
        $child  = $this->makeRole('editor', parentId: $parent->getKey());

        $this->makePermission('posts:delete');
        $this->makePermission('posts:create');

        $parent->givePermission('posts:delete');
        $child->givePermission('posts:create');

        self::assertSame(['posts:create'], $child->fresh()->getPermissions());
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
        self::assertTrue($ancestors->first()->is($root));
        self::assertTrue($ancestors->last()->is($middle));
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

        $ids = $descendants->map(fn (Role $r): string => (string) $r->getKey())->all();

        self::assertContains((string) $middle->getKey(), $ids);
        self::assertContains((string) $leaf->getKey(), $ids);
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
