<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\GrantRoleCommand;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the `authorization:grant` Artisan command.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantRoleCommand::class)]
final class GrantRoleCommandTest extends TestCase
{
    /**
     * Successfully grants a role to an identity via morph alias.
     *
     * @return void
     */
    public function testGrantsRoleViaMorphAlias(): void
    {
        Relation::morphMap(['stub_identity' => StubIdentity::class]);

        Role::create(['id' => '01J0000000000000000000GROL', 'name' => 'editor', 'guard_name' => 'web']);
        $user = StubIdentity::create(['id' => '01J0000000000000000000GUSR']);

        $exitCode = Artisan::call('authorization:grant', [
            'identity' => 'stub_identity:01J0000000000000000000GUSR',
            'role'     => 'editor',
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('granted', Artisan::output());
        /** @var \Tests\Feature\Stubs\StubIdentity $freshUser */
        $freshUser = $user->fresh();
        self::assertTrue($freshUser->hasRole('editor'));

        // Reset the shared morph map — `morphMap([])` merges rather
        // than replaces, so without the `false` second arg the
        // `stub_identity` alias leaks into later tests in the run.
        Relation::morphMap([], false);
    }

    /**
     * Successfully grants a role via raw class-string.
     *
     * @return void
     */
    public function testGrantsRoleViaClassName(): void
    {
        Role::create(['id' => '01J0000000000000000000GRO2', 'name' => 'admin', 'guard_name' => 'web']);
        StubIdentity::create(['id' => '01J0000000000000000000GUS2']);

        $exitCode = Artisan::call('authorization:grant', [
            'identity' => StubIdentity::class . ':01J0000000000000000000GUS2',
            'role'     => 'admin',
        ]);

        self::assertSame(0, $exitCode);
        /** @var \Tests\Feature\Stubs\StubIdentity $found */
        $found = StubIdentity::find('01J0000000000000000000GUS2');
        self::assertTrue($found->hasRole('admin'));
    }

    /**
     * Fails on invalid identity format.
     *
     * @return void
     */
    public function testFailsOnInvalidIdentityFormat(): void
    {
        $exitCode = Artisan::call('authorization:grant', [
            'identity' => 'no-colon',
            'role'     => 'editor',
        ]);

        self::assertSame(1, $exitCode);
    }

    /**
     * Fails when class cannot be resolved.
     *
     * @return void
     */
    public function testFailsOnUnresolvableClass(): void
    {
        $exitCode = Artisan::call('authorization:grant', [
            'identity' => 'NonExistentClass:1',
            'role'     => 'editor',
        ]);

        self::assertSame(1, $exitCode);
    }

    /**
     * Fails when model does not exist in the database.
     *
     * @return void
     */
    public function testFailsWhenModelNotFound(): void
    {
        $exitCode = Artisan::call('authorization:grant', [
            'identity' => StubIdentity::class . ':missing',
            'role'     => 'editor',
        ]);

        self::assertSame(1, $exitCode);
    }

    /**
     * Fails when role does not exist.
     *
     * @return void
     */
    public function testFailsWhenRoleDoesNotExist(): void
    {
        StubIdentity::create(['id' => '01J0000000000000000000GUS3']);

        $exitCode = Artisan::call('authorization:grant', [
            'identity' => StubIdentity::class . ':01J0000000000000000000GUS3',
            'role'     => 'nonexistent',
        ]);

        self::assertSame(1, $exitCode);
    }
}
