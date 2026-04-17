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
}
