<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\ListRolesCommand;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\TestCase;

/**
 * Feature tests for the `authorization:list-roles` Artisan command.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ListRolesCommand::class)]
final class ListRolesCommandTest extends TestCase
{
    /**
     * Command outputs a table of roles.
     *
     * @return void
     */
    public function testListsAllRoles(): void
    {
        $role = Role::create([
            'id'         => '0c0045ec-a918-4272-83ae-f5d7afa6d6ee',
            'name'       => 'admin',
            'guard_name' => 'web',
            'is_system'  => true,
        ]);

        $permission = Permission::create([
            'id'         => 'f9ba2d63-6080-4337-848b-300ba8ddf2b8',
            'name'       => 'posts:create',
            'guard_name' => 'web',
        ]);

        $role->permissions()->attach($permission->getKey());

        $exitCode = Artisan::call('authorization:list-roles');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('admin', $output);
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
        Role::create(['id' => '25615f6f-958a-454d-8fbe-18897de1f95c', 'name' => 'web-role', 'guard_name' => 'web']);
        Role::create(['id' => '895d173b-0e19-45a1-80f8-320bd067e6e3', 'name' => 'api-role', 'guard_name' => 'api']);

        $exitCode = Artisan::call('authorization:list-roles', ['--guard' => 'api']);
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('api-role', $output);
        self::assertStringNotContainsString('web-role', $output);
    }

    /**
     * Command displays info message when no roles exist.
     *
     * @return void
     */
    public function testDisplaysInfoWhenNoRoles(): void
    {
        $exitCode = Artisan::call('authorization:list-roles');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('No roles found', $output);
    }
}
