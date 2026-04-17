<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use SineMacula\Laravel\Authorization\Resolvers\NullTenantResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use SineMacula\Laravel\Authorization\Traits\HasRoleHierarchy;
use SineMacula\Laravel\Authorization\Traits\ManagesPermissions;
use Tests\TestCase;

/**
 * Coverage for two `Role` model branches that the primary suites
 * do not exercise:
 *
 * - `givePermission()` and `syncPermissions()` clear the eager-loaded
 *   `permissions` relation when mutation occurs, so subsequent
 *   reads re-hydrate from the pivot. The clear branch only fires
 *   when the caller has in fact loaded the relation — the
 *   RBAC-heavy suites all mutate before loading, so the branch
 *   stays cold.
 * - `resolvePermissionById()` raises `UnknownPermissionException`
 *   when the sync delta surfaces a detached ID whose row has been
 *   deleted. This race can only happen under a concurrent DELETE
 *   between the sync call and the event-dispatch loop.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Role::class)]
#[CoversClass(RoleObserver::class)]
#[CoversClass(TenantScope::class)]
#[CoversClass(NullTenantResolver::class)]
#[CoversClass(ResolutionCacheContext::class)]
#[CoversClass(InvalidTenantException::class)]
#[CoversClass(InvalidTenantColumnsException::class)]
#[CoversClass(GuardScopedLookup::class)]
#[CoversTrait(HasRoleHierarchy::class)]
#[CoversTrait(ManagesPermissions::class)]
final class RoleModelEdgeCasesTest extends TestCase
{
    /**
     * `givePermission()` evicts the eager-loaded permissions
     * relation so the next access re-queries the pivot.
     *
     * @return void
     */
    public function testGivePermissionEvictsLoadedRelation(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'editor-evict',
            'guard_name' => 'web',
        ]);

        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'posts:create',
            'guard_name' => 'web',
        ]);

        // Pre-load the relation so the eviction branch of
        // givePermission() fires.
        $role->load('permissions');
        self::assertTrue($role->relationLoaded('permissions'));

        $role->givePermission('posts:create');

        self::assertFalse($role->relationLoaded('permissions'));
    }

    /**
     * `syncPermissions()` evicts the eager-loaded permissions
     * relation after the sync completes.
     *
     * @return void
     */
    public function testSyncPermissionsEvictsLoadedRelation(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'editor-sync-evict',
            'guard_name' => 'web',
        ]);

        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'posts:create',
            'guard_name' => 'web',
        ]);

        $role->load('permissions');
        self::assertTrue($role->relationLoaded('permissions'));

        $role->syncPermissions(['posts:create']);

        self::assertFalse($role->relationLoaded('permissions'));
    }

    /**
     * When a role's `parent_id` points at a row that has been
     * deleted out from under it (orphaned FK), `ancestors()`
     * breaks the walk at the missing link rather than throwing.
     * Protects consumers against a corrupted hierarchy surfacing
     * as an exception during evaluation.
     *
     * @return void
     */
    public function testAncestorsStopsAtOrphanedParent(): void
    {
        $parent = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'orphan-parent',
            'guard_name' => 'web',
        ]);

        $child = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'orphan-child',
            'guard_name' => 'web',
            'parent_id'  => $parent->getKey(),
        ]);

        // Simulate a detached parent row without running through the
        // model's delete pipeline (which would nullify children).
        DB::table('roles')->where('id', $parent->getKey())->delete();

        $ancestors = $child->fresh()?->ancestors();

        self::assertNotNull($ancestors);
        self::assertCount(0, $ancestors);
    }

    /**
     * `resolvePermissionById()` raises `UnknownPermissionException`
     * when the supplied key does not resolve to a row. The public
     * sync surface cannot reach this directly without a racing
     * delete, so the test invokes the method via reflection against
     * a key that does not exist.
     *
     * @return void
     */
    public function testResolvePermissionByIdThrowsOnMissingRow(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'editor-missing-perm',
            'guard_name' => 'web',
        ]);

        $reflection = new \ReflectionMethod($role, 'resolvePermissionById');
        $reflection->setAccessible(true);

        $this->expectException(UnknownPermissionException::class);

        $reflection->invoke($role, '00000000-0000-4000-8000-000000000000');
    }
}
