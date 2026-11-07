<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\RevokeRoleCommand;
use SineMacula\Laravel\Authorization\Events\Identity\RoleRevoked;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the `authorization:revoke` Artisan command.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
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
        Role::create(['id' => 'c7916105-9686-4752-8e5f-2370eb494a02', 'name' => 'editor', 'guard' => 'web']);
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

    /**
     * A failed revoke outputs the exception message. Pins the MethodCallRemoval
     * mutant on line 65 of RevokeRoleCommand.
     *
     * @return void
     */
    public function testFailedRevokeOutputsErrorMessage(): void
    {
        StubIdentity::create(['id' => 'b1b1b1b1-0000-0000-0000-000000000001']);

        $exitCode = Artisan::call('authorization:revoke', [
            'identity' => StubIdentity::class . ':b1b1b1b1-0000-0000-0000-000000000001',
            'role'     => 'does-not-exist',
        ]);
        $output = Artisan::output();

        self::assertSame(1, $exitCode);
        self::assertNotEmpty(\trim($output), 'Error message must be printed on failure.');
    }

    /**
     * Success message includes both the role name and identity arg. Pins the
     * ReturnRemoval on line 59.
     *
     * @return void
     */
    public function testSuccessMessageIncludesRoleAndIdentity(): void
    {
        Role::create(['id' => 'b2b2b2b2-0000-0000-0000-000000000001', 'name' => 'rev-role', 'guard' => 'web']);
        $user = StubIdentity::create(['id' => 'b3b3b3b3-0000-0000-0000-000000000001']);
        $user->assignRole('rev-role');

        $identity = StubIdentity::class . ':b3b3b3b3-0000-0000-0000-000000000001';
        $exitCode = Artisan::call('authorization:revoke', [
            'identity' => $identity,
            'role'     => 'rev-role',
        ]);
        $output = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('rev-role', $output);
        self::assertStringContainsString($identity, $output);
    }

    /**
     * Without a resolved tenant the role is looked up among platform-wide roles
     * only, so a tenant-owned role is not found.
     *
     * @return void
     */
    public function testTenantOwnedRoleIsNotFoundWithoutATenant(): void
    {
        Role::create([
            'id'          => 'e3e3e3e3-0000-0000-0000-000000000001',
            'name'        => 'owned-editor',
            'guard'       => 'web',
            'tenant_type' => 'tenant',
            'tenant_id'   => 't-1',
        ]);
        StubIdentity::create(['id' => 'e4e4e4e4-0000-0000-0000-000000000001']);

        $exitCode = Artisan::call('authorization:revoke', [
            'identity' => StubIdentity::class . ':e4e4e4e4-0000-0000-0000-000000000001',
            'role'     => 'owned-editor',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('owned-editor', Artisan::output());
    }

    /**
     * Revoking a role the identity does not hold reports it as not held,
     * succeeds and dispatches nothing.
     *
     * @return void
     */
    public function testReportsARoleThatIsNotHeld(): void
    {
        Role::query()->create(['name' => 'editor', 'guard' => 'web']);
        StubIdentity::create(['id' => 'b1b1b1b1-0000-0000-0000-000000000002']);

        Event::fake([RoleRevoked::class]);

        $identity = StubIdentity::class . ':b1b1b1b1-0000-0000-0000-000000000002';
        $exitCode = Artisan::call('authorization:revoke', ['identity' => $identity, 'role' => 'editor']);

        self::assertSame(0, $exitCode);
        self::assertSame("{$identity} does not hold role 'editor'.", \trim(Artisan::output()));
        Event::assertNotDispatched(RoleRevoked::class);
    }

    /**
     * `--actor` names the actor making the revocation, which is then decided as
     * delegated administration: a revocation of a role no deny is attached to
     * only narrows, so an actor allowed `authorization:role.revoke` makes it,
     * and its event carries the actor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReportsTheActorTheOptionNames(): void
    {
        $role = Role::create(['name' => 'editor', 'guard' => 'web']);
        $user = StubIdentity::create(['id' => 'user-1']);

        StubIdentity::create(['id' => 'admin-1'])->givePermission(Permission::create(['name' => PackagePermissions::ROLE_REVOKE]));
        app(GrantService::class)->grantRole($user, $role);

        Event::fake([RoleRevoked::class]);

        self::assertSame(
            0,
            Artisan::call('authorization:revoke', ['identity' => StubIdentity::class . ':user-1', 'role' => 'editor', '--actor' => StubIdentity::class . ':admin-1']),
        );

        Event::assertDispatched(RoleRevoked::class, static fn (RoleRevoked $event): bool => $event->operation->actor?->type === StubIdentity::class
            && $event->operation->actor->id                                                                                 === 'admin-1');
    }

    /**
     * An actor the option cannot resolve fails the command and revokes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testFailsOnAnActorItCannotResolve(): void
    {
        $role = Role::create(['name' => 'editor', 'guard' => 'web']);
        $user = StubIdentity::create(['id' => 'user-1']);

        app(GrantService::class)->grantRole($user, $role);

        self::assertSame(
            1,
            Artisan::call('authorization:revoke', ['identity' => StubIdentity::class . ':user-1', 'role' => 'editor', '--actor' => StubIdentity::class . ':ghost']),
        );
        self::assertSame(1, DB::table('authorizable_roles')->count());
    }
}
