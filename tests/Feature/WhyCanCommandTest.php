<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
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
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(WhyCanCommand::class)]
final class WhyCanCommandTest extends TestCase
{
    /**
     * Reports ALLOWED when the identity holds the permission through a role: no
     * reason, the allow stage, and a trace ending in the permission held.
     *
     * @return void
     */
    public function testReportsAllowedViaRbac(): void
    {
        $role       = Role::create(['id' => 'b0f398ae-5148-47f4-87f6-de35c0472093', 'name' => 'editor', 'guard' => 'web']);
        $permission = Permission::create(['id' => '030ab20c-62a1-4c84-87e2-9f77cdc856c0', 'name' => 'posts:edit', 'guard' => 'web']);
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
        self::assertStringContainsString('  Reason:   (none)', $output);
        self::assertStringContainsString('  Stage:    allow', $output);
        self::assertStringContainsString("  Trace:\n    [allow] permission: held\n", $output);
    }

    /**
     * Reports DENIED when the identity has no permission: nothing names the
     * action, at the implicit stage, and the trace records the permission not
     * held.
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
        self::assertStringContainsString('  Reason:   no_match', $output);
        self::assertStringContainsString('  Stage:    implicit', $output);
        self::assertStringContainsString("  Trace:\n    [allow] permission: not_held\n", $output);
    }

    /**
     * Reports DENIED when an explicit deny policy overrides RBAC, decided at
     * the deny stage by the deny statement.
     *
     * @return void
     */
    public function testReportsDeniedFromExplicitDenyPolicy(): void
    {
        $role       = Role::create(['id' => 'cc63f23a-abaf-4fe7-8244-dff37bb878a6', 'name' => 'admin', 'guard' => 'web']);
        $permission = Permission::create(['id' => 'ac3459db-f8a4-410a-80c6-1c2412a8f324', 'name' => 'posts:delete', 'guard' => 'web']);
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
        self::assertStringContainsString('  Reason:   explicit_deny', $output);
        self::assertStringContainsString('  Stage:    deny', $output);
        self::assertStringContainsString("    [deny] deny-delete[{$policy->id}]#0: matched", $output);
        self::assertStringNotContainsString('permission:', $output);
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

    /**
     * Output includes the Result, Reason, Stage, Action and Resource labels, in
     * that order. Pins the MethodCallRemoval and Concat mutants on the lines
     * that print them.
     *
     * @return void
     */
    public function testOutputIncludesActionAndResourceLabels(): void
    {
        StubIdentity::create(['id' => 'd0d0d0d0-0000-0000-0000-000000000001']);

        $exitCode = Artisan::call('authorization:why-can', [
            'identity' => StubIdentity::class . ':d0d0d0d0-0000-0000-0000-000000000001',
            'action'   => 'custom:action',
        ]);
        $output = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Action:   custom:action', $output);
        self::assertStringContainsString('Resource: (none)', $output);
        self::assertStringContainsString('Reason:', $output);
        self::assertStringContainsString('Result:', $output);
        self::assertMatchesRegularExpression('/  Result:   DENIED\n  Reason:   no_match\n  Stage:    implicit\n  Action:   custom:action\n  Resource: \(none\)\n/', $output);
    }

    /**
     * The `verdictColor` private method returns 'green' for allowed and 'red'
     * for denied. Pins the Ternary mutant in it.
     *
     * @return void
     */
    public function testVerdictColorReturnsCorrectValues(): void
    {
        $command = new WhyCanCommand;
        $ref     = new \ReflectionMethod($command, 'verdictColor');

        self::assertSame('green', $ref->invoke($command, true));
        self::assertSame('red', $ref->invoke($command, false));
    }

    /**
     * The trace output prints each entry indented on its own line, with its
     * stage, policy, statement index and outcome, the deny stage before the
     * allow stage. No deny decides, so both stages are traced. Pins the
     * Foreach_ and MethodCallRemoval mutants on the trace loop.
     *
     * @return void
     */
    public function testTraceOutputIncludesEntries(): void
    {
        $policy = Policy::create([
            'id'       => 'f1f1f1f1-0000-0000-0000-000000000001',
            'name'     => 'trace-policy',
            'document' => [
                'name'       => 'trace-policy',
                'statements' => [
                    ['effect' => 'deny', 'actions' => ['other:action']],
                    ['effect' => 'allow', 'actions' => ['trace:action']],
                ],
            ],
        ]);

        $user = StubIdentity::create(['id' => 'f2f2f2f2-0000-0000-0000-000000000001']);
        $user->attachPolicy($policy);

        $exitCode = Artisan::call('authorization:why-can', [
            'identity' => StubIdentity::class . ':f2f2f2f2-0000-0000-0000-000000000001',
            'action'   => 'trace:action',
        ]);
        $output = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString("  Trace:\n    [deny] trace-policy[{$policy->id}]#0: not_applicable\n    [allow] trace-policy[{$policy->id}]#1: matched\n", $output);
    }

    /**
     * A decision with an empty trace, here the denial for an identity holding a
     * policy document that cannot be read, prints no "Trace:" section. Pins the
     * NotIdentical mutant on `$decision->trace !== []`.
     *
     * @return void
     */
    public function testEmptyTraceOmitsTraceSection(): void
    {
        $user = StubIdentity::create(['id' => 'f3f3f3f3-0000-0000-0000-000000000001']);

        DB::table('policies')->insert([
            'id'         => 'f4f4f4f4-0000-0000-0000-000000000001',
            'name'       => 'unreadable',
            'document'   => \json_encode(['malformed' => true]),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('authorizable_policies')->insert([
            'policy_id'         => 'f4f4f4f4-0000-0000-0000-000000000001',
            'authorizable_type' => $user->getMorphClass(),
            'authorizable_id'   => 'f3f3f3f3-0000-0000-0000-000000000001',
        ]);

        $exitCode = Artisan::call('authorization:why-can', [
            'identity' => StubIdentity::class . ':f3f3f3f3-0000-0000-0000-000000000001',
            'action'   => 'no:match',
        ]);
        $output = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('  Reason:   invalid_policy', $output);
        self::assertStringContainsString('  Stage:    deny', $output);
        self::assertStringNotContainsString('Trace:', $output);
    }
}
