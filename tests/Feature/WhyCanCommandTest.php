<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
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
final class WhyCanCommandTest extends TestCase
{
    /**
     * Reports ALLOWED when identity has RBAC permission.
     *
     * @return void
     */
    public function testReportsAllowedViaRbac(): void
    {
        $role       = Role::create(['id' => 'b0f398ae-5148-47f4-87f6-de35c0472093', 'name' => 'editor', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => '030ab20c-62a1-4c84-87e2-9f77cdc856c0', 'name' => 'posts:edit', 'guard_name' => 'web']);
        $role->permissions()->attach($permission->getKey());

        $user = StubIdentity::create(['id' => '9db25f66-208f-4f49-858f-7434e5982961']);
        $user->assignRole('editor');

        $exitCode = Artisan::call('authorization:why-can', [
            'identity' => StubIdentity::class . ':9db25f66-208f-4f49-858f-7434e5982961',
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
        StubIdentity::create(['id' => 'b41330b3-b19e-409b-8d85-1e1eafbbbdb8']);

        $exitCode = Artisan::call('authorization:why-can', [
            'identity' => StubIdentity::class . ':b41330b3-b19e-409b-8d85-1e1eafbbbdb8',
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
        $role       = Role::create(['id' => 'cc63f23a-abaf-4fe7-8244-dff37bb878a6', 'name' => 'admin', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => 'ac3459db-f8a4-410a-80c6-1c2412a8f324', 'name' => 'posts:delete', 'guard_name' => 'web']);
        $role->permissions()->attach($permission->getKey());

        $policy = Policy::create([
            'id'       => '3f6c67e2-e4b8-46bc-8d60-83b1c97c3044',
            'name'     => 'deny-delete',
            'document' => [
                'name'       => 'deny-delete',
                'statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]],
            ],
        ]);

        $user = StubIdentity::create(['id' => 'c42bf7e4-de42-476d-87c1-ae438ca8c05d']);
        $user->assignRole('admin');
        $user->attachPolicy($policy);

        $exitCode = Artisan::call('authorization:why-can', [
            'identity' => StubIdentity::class . ':c42bf7e4-de42-476d-87c1-ae438ca8c05d',
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
        StubIdentity::create(['id' => 'feae9208-1bcc-49b0-830d-d70871c6eb41']);

        $exitCode = Artisan::call('authorization:why-can', [
            'identity' => StubIdentity::class . ':feae9208-1bcc-49b0-830d-d70871c6eb41',
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
