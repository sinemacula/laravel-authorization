<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\ListPermissionsCommand;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\TestCase;

/**
 * Feature tests for the `authorization:list-permissions` Artisan command.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ListPermissionsCommand::class)]
final class ListPermissionsCommandTest extends TestCase
{
    /**
     * Command outputs a table of permissions.
     *
     * @return void
     */
    public function testListsAllPermissions(): void
    {
        $permission = Permission::create([
            'id'         => 'ce531769-59b0-4882-8032-8e1bec3f6be3',
            'name'       => 'posts:create',
            'guard_name' => 'web',
            'is_system'  => true,
        ]);

        $role = Role::create([
            'id'         => '2298f05e-8e84-4d89-8853-0c77a714b221',
            'name'       => 'editor',
            'guard_name' => 'web',
        ]);

        $role->permissions()->attach($permission->getKey());

        $exitCode = Artisan::call('authorization:list-permissions');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('posts:create', $output);
        self::assertStringContainsString('web', $output);
        self::assertStringContainsString('Yes', $output);
    }

    /**
     * Command filters by guard name.
     *
     * @return void
     */
    public function testFiltersByGuard(): void
    {
        Permission::create(['id' => '0bbc4051-26a7-46ba-84bb-1c83d2269a7e', 'name' => 'web:do', 'guard_name' => 'web']);
        Permission::create(['id' => '5843b7ec-50c9-45cd-8c4b-6032a53b343b', 'name' => 'api:do', 'guard_name' => 'api']);

        $exitCode = Artisan::call('authorization:list-permissions', ['--guard' => 'api']);
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('api:do', $output);
        self::assertStringNotContainsString('web:do', $output);
    }

    /**
     * Command displays info message when no permissions exist.
     *
     * @return void
     */
    public function testDisplaysInfoWhenNoPermissions(): void
    {
        $exitCode = Artisan::call('authorization:list-permissions');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('No permissions found', $output);
    }

    /**
     * The table output includes ID, name, guard, system flag, and
     * role count columns. Pins the ArrayItemRemoval mutants on
     * lines 69 and 74, and the CastString on line 79.
     *
     * @return void
     */
    public function testTableOutputIncludesAllColumns(): void
    {
        $permission = Permission::create([
            'id'         => 'd1d1d1d1-0000-0000-0000-000000000001',
            'name'       => 'col:perm',
            'guard_name' => 'web',
            'is_system'  => false,
        ]);

        $r1 = Role::create(['id' => 'd2d2d2d2-0000-0000-0000-000000000001', 'name' => 'col-r1', 'guard_name' => 'web']);
        $r2 = Role::create(['id' => 'd3d3d3d3-0000-0000-0000-000000000001', 'name' => 'col-r2', 'guard_name' => 'web']);
        $r1->permissions()->attach($permission->getKey());
        $r2->permissions()->attach($permission->getKey());

        $exitCode = Artisan::call('authorization:list-permissions');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        // Verify headers and data columns are present.
        self::assertStringContainsString('ID', $output);
        self::assertStringContainsString('Name', $output);
        self::assertStringContainsString('Guard', $output);
        self::assertStringContainsString('System', $output);
        self::assertStringContainsString('Roles', $output);
        self::assertStringContainsString('col:perm', $output);
        self::assertStringContainsString('web', $output);
        self::assertStringContainsString('No', $output);
        self::assertStringContainsString('2', $output);
    }

    /**
     * A permission with null guard_name renders "(any)".
     *
     * @return void
     */
    public function testNullGuardRendersAny(): void
    {
        Permission::create([
            'id'         => 'd4d4d4d4-0000-0000-0000-000000000001',
            'name'       => 'null-guard-perm',
            'guard_name' => null,
        ]);

        $exitCode = Artisan::call('authorization:list-permissions');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('(any)', $output);
    }

    /**
     * The ReturnRemoval mutant on line 65 is killed by verifying
     * the command returns SUCCESS (0).
     *
     * @return void
     */
    public function testReturnsSuccessExitCode(): void
    {
        Permission::create(['id' => 'd5d5d5d5-0000-0000-0000-000000000001', 'name' => 'exit:perm', 'guard_name' => 'web']);

        $exitCode = Artisan::call('authorization:list-permissions');

        self::assertSame(0, $exitCode);
    }
}
