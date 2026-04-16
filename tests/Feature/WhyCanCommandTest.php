<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\Concerns\ResolvesIdentity;
use SineMacula\Laravel\Authorization\Console\WhyCanCommand;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the `authorization:why-can` Artisan command.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(WhyCanCommand::class)]
#[CoversClass(ResolvesIdentity::class)]
final class WhyCanCommandTest extends TestCase
{
    /**
     * Reports ALLOWED when identity has RBAC permission.
     *
     * @return void
     */
    public function testReportsAllowedViaRbac(): void
    {
        $role       = Role::create(['id' => '01J0000000000000000000WROL', 'name' => 'editor', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => '01J0000000000000000000WPER', 'name' => 'posts:edit', 'guard_name' => 'web']);
        $role->permissions()->attach($permission->getKey());

        $user = StubIdentity::create(['id' => '01J0000000000000000000WUSR']);
        $user->assignRole('editor');

        $exitCode = Artisan::call('authorization:why-can', [
            'identity' => StubIdentity::class . ':01J0000000000000000000WUSR',
            'action'   => 'posts:edit',
        ]);
        $output = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('ALLOWED', $output);
        self::assertStringContainsString('rbac_allow', $output);
    }

    /**
     * Reports DENIED when identity has no permission.
     *
     * @return void
     */
    public function testReportsDeniedWhenNoPermission(): void
    {
        StubIdentity::create(['id' => '01J0000000000000000000WUS2']);

        $exitCode = Artisan::call('authorization:why-can', [
            'identity' => StubIdentity::class . ':01J0000000000000000000WUS2',
            'action'   => 'posts:delete',
        ]);
        $output = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('DENIED', $output);
        self::assertStringContainsString('implicit_deny', $output);
    }

    /**
     * Reports DENIED when explicit deny policy overrides RBAC.
     *
     * @return void
     */
    public function testReportsDeniedFromExplicitDenyPolicy(): void
    {
        $role       = Role::create(['id' => '01J0000000000000000000WRO2', 'name' => 'admin', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => '01J0000000000000000000WPE2', 'name' => 'posts:delete', 'guard_name' => 'web']);
        $role->permissions()->attach($permission->getKey());

        $policy = Policy::create([
            'id'       => '01J0000000000000000000WPOL',
            'name'     => 'deny-delete',
            'document' => [
                'name'       => 'deny-delete',
                'statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]],
            ],
        ]);

        $user = StubIdentity::create(['id' => '01J0000000000000000000WUS3']);
        $user->assignRole('admin');
        $user->attachPolicy($policy);

        $exitCode = Artisan::call('authorization:why-can', [
            'identity' => StubIdentity::class . ':01J0000000000000000000WUS3',
            'action'   => 'posts:delete',
        ]);
        $output = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('DENIED', $output);
        self::assertStringContainsString('explicit_deny', $output);
    }

    /**
     * Accepts an optional resource argument.
     *
     * @return void
     */
    public function testAcceptsOptionalResource(): void
    {
        StubIdentity::create(['id' => '01J0000000000000000000WUS4']);

        $exitCode = Artisan::call('authorization:why-can', [
            'identity' => StubIdentity::class . ':01J0000000000000000000WUS4',
            'action'   => 'posts:edit',
            'resource' => 'post:42',
        ]);
        $output = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('post:42', $output);
    }

    /**
     * Fails on invalid identity format.
     *
     * @return void
     */
    public function testFailsOnInvalidIdentity(): void
    {
        $exitCode = Artisan::call('authorization:why-can', [
            'identity' => 'bad',
            'action'   => 'posts:edit',
        ]);

        self::assertSame(1, $exitCode);
    }
}
