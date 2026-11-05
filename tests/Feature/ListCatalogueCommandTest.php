<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\ListCatalogueCommand;
use SineMacula\Laravel\Authorization\Console\ListPermissionsCommand;
use SineMacula\Laravel\Authorization\Console\ListRolesCommand;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\TestCase;

/**
 * Feature tests for the shared body of the role and permission listings.
 *
 * Each row is pinned whole: ID, name, guard, owner, system flag and the count
 * of related records across every owner.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ListCatalogueCommand::class)]
#[CoversClass(ListRolesCommand::class)]
#[CoversClass(ListPermissionsCommand::class)]
final class ListCatalogueCommandTest extends TestCase
{
    /**
     * An empty listing says so in the listing's own words.
     *
     * @return void
     */
    public function testEmptyListingsNameTheirRecords(): void
    {
        self::assertSame(0, Artisan::call('authorization:list-roles'));
        self::assertSame("No roles found.\n", Artisan::output());

        self::assertSame(0, Artisan::call('authorization:list-permissions'));
        self::assertSame("No permissions found.\n", Artisan::output());
    }

    /**
     * Every role is listed with its owner, system flag and the permissions it
     * holds, counted across every owner; a role without a guard shows `(any)`.
     *
     * @return void
     */
    public function testRoleRowsArePinnedWhole(): void
    {
        $platform = Role::create(['name' => 'editor', 'guard' => 'web', 'is_system' => true]);
        $viewer   = Role::create(['name' => 'viewer', 'tenant_type' => 'tenant', 'tenant_id' => 't-1']);

        $owned  = Permission::create(['name' => 'posts:edit', 'guard' => 'web', 'tenant_type' => 'tenant', 'tenant_id' => 't-1']);
        $shared = Permission::create(['name' => 'posts:read', 'guard' => 'web']);

        $platform->permissions()->attach([$owned->id, $shared->id]);

        self::assertSame(0, Artisan::call('authorization:list-roles'));

        $output = Artisan::output();

        self::assertMatchesRegularExpression('/\|\s*ID\s*\|\s*Name\s*\|\s*Guard\s*\|\s*Owner\s*\|\s*System\s*\|\s*Permissions\s*\|/', $output);
        self::assertMatchesRegularExpression('/\|\s*' . $platform->id . '\s*\|\s*editor\s*\|\s*web\s*\|\s*platform\s*\|\s*Yes\s*\|\s*2\s*\|/', $output);
        self::assertMatchesRegularExpression('/\|\s*' . $viewer->id . '\s*\|\s*viewer\s*\|\s*\(any\)\s*\|\s*tenant:t-1\s*\|\s*No\s*\|\s*0\s*\|/', $output);
    }

    /**
     * Every permission is listed with the roles that hold it, under a `Roles`
     * heading.
     *
     * @return void
     */
    public function testPermissionRowsCountTheirRoles(): void
    {
        $permission = Permission::create(['name' => 'posts:edit', 'guard' => 'web']);

        Role::create(['name' => 'editor', 'guard' => 'web', 'tenant_type' => 'tenant', 'tenant_id' => 't-2'])
            ->permissions()->attach($permission->id);

        self::assertSame(0, Artisan::call('authorization:list-permissions'));

        $output = Artisan::output();

        self::assertMatchesRegularExpression('/\|\s*ID\s*\|\s*Name\s*\|\s*Guard\s*\|\s*Owner\s*\|\s*System\s*\|\s*Roles\s*\|/', $output);
        self::assertMatchesRegularExpression('/\|\s*' . $permission->id . '\s*\|\s*posts:edit\s*\|\s*web\s*\|\s*platform\s*\|\s*No\s*\|\s*1\s*\|/', $output);
    }

    /**
     * The guard filter keeps only rows of that guard, and an empty guard
     * filters nothing.
     *
     * @return void
     */
    public function testGuardFilter(): void
    {
        Role::create(['name' => 'web-role', 'guard' => 'web']);
        Role::create(['name' => 'api-role', 'guard' => 'api']);

        Artisan::call('authorization:list-roles', ['--guard' => 'api']);
        $filtered = Artisan::output();

        self::assertStringContainsString('api-role', $filtered);
        self::assertStringNotContainsString('web-role', $filtered);

        Artisan::call('authorization:list-roles', ['--guard' => '']);
        $unfiltered = Artisan::output();

        self::assertStringContainsString('api-role', $unfiltered);
        self::assertStringContainsString('web-role', $unfiltered);
    }

    /**
     * Rows are listed by name.
     *
     * @return void
     */
    public function testRowsAreOrderedByName(): void
    {
        Role::create(['name' => 'zeta', 'guard' => 'web']);
        Role::create(['name' => 'alpha', 'guard' => 'web']);

        Artisan::call('authorization:list-roles');
        $output = Artisan::output();

        self::assertLessThan(\strpos($output, 'zeta'), \strpos($output, 'alpha'));
    }
}
