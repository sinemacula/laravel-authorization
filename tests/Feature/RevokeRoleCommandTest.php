<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\RevokeRoleCommand;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the `authorization:revoke` Artisan command.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevokeRoleCommand::class)]
final class RevokeRoleCommandTest extends TestCase
{
    /**
     * Successfully revokes a role from an identity.
     *
     * @return void
     */
    public function testRevokesRoleFromIdentity(): void
    {
        Role::create(['id' => 'c7916105-9686-4752-8e5f-2370eb494a02', 'name' => 'editor', 'guard_name' => 'web']);
        $user = StubIdentity::create(['id' => '0e4acbbb-88e6-47d4-8ed1-93b6f54a4a44']);
        $user->assignRole('editor');

        self::assertTrue($user->hasRole('editor'));

        $exitCode = Artisan::call('authorization:revoke', [
            'identity' => StubIdentity::class . ':0e4acbbb-88e6-47d4-8ed1-93b6f54a4a44',
            'role'     => 'editor',
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('revoked', Artisan::output());
        /** @var \Tests\Feature\Stubs\StubIdentity $freshUser */
        $freshUser = $user->fresh();
        self::assertFalse($freshUser->hasRole('editor'));
    }

    /**
     * Fails on invalid identity format.
     *
     * @return void
     */
    public function testFailsOnInvalidIdentityFormat(): void
    {
        $exitCode = Artisan::call('authorization:revoke', [
            'identity' => 'bad-format',
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
        StubIdentity::create(['id' => 'e8afdc3b-ab3b-4603-857e-a38b28b2f537']);

        $exitCode = Artisan::call('authorization:revoke', [
            'identity' => StubIdentity::class . ':e8afdc3b-ab3b-4603-857e-a38b28b2f537',
            'role'     => 'nonexistent',
        ]);

        self::assertSame(1, $exitCode);
    }
}
