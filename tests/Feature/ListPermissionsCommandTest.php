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
            'id'         => '01J0000000000000000000LPEA',
            'name'       => 'posts:create',
            'guard_name' => 'web',
            'is_system'  => true,
        ]);

        $role = Role::create([
            'id'         => '01J0000000000000000000LROA',
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
        Permission::create(['id' => '01J0000000000000000000LPE2', 'name' => 'web:do', 'guard_name' => 'web']);
        Permission::create(['id' => '01J0000000000000000000LPE3', 'name' => 'api:do', 'guard_name' => 'api']);

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
}
