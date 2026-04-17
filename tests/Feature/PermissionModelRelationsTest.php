<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\PermissionObserver;
use SineMacula\Laravel\Authorization\Resolvers\NullTenantResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use Tests\TestCase;

/**
 * Coverage for the `Permission` model's reverse-role relation and
 * the `resolveByName()` unknown-name branch that is not otherwise
 * reached from the role-scoped test suites.
 *
 * The `roles()` accessor drives reverse navigation — consumers who
 * have a permission in hand and want to know which roles carry it —
 * and its binding reads the swappable model class and pivot table
 * names from the shipped config, so the relation must be exercised
 * end-to-end (config lookup + pivot navigation + attached roles).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Permission::class)]
#[CoversClass(PermissionObserver::class)]
#[CoversClass(TenantScope::class)]
#[CoversClass(NullTenantResolver::class)]
#[CoversClass(ResolutionCacheContext::class)]
#[CoversClass(InvalidTenantException::class)]
#[CoversClass(InvalidTenantColumnsException::class)]
#[CoversClass(GuardScopedLookup::class)]
final class PermissionModelRelationsTest extends TestCase
{
    /**
     * `Permission::roles()` returns every role that has the
     * permission attached via the role-permission pivot.
     *
     * @return void
     */
    public function testRolesRelationReturnsAttachedRoles(): void
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'editor',
            'guard_name' => 'web',
        ]);

        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'posts:create',
            'guard_name' => 'web',
        ]);

        $role->givePermission($permission);

        $carriers = $permission->roles()->get();

        self::assertCount(1, $carriers);
        self::assertSame($role->getKey(), $carriers->first()?->getKey());
    }

    /**
     * `Permission::resolveByName()` raises
     * `UnknownPermissionException` when no row matches — the typed
     * failure surface documented for the shared resolution helper.
     *
     * @return void
     */
    public function testResolveByNameThrowsOnUnknownPermission(): void
    {
        $this->expectException(UnknownPermissionException::class);

        Permission::resolveByName('does:not-exist', 'web');
    }
}
