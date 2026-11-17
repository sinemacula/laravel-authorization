<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Role\PermissionGranted;
use SineMacula\Laravel\Authorization\Events\SystemOverrideUsed;
use SineMacula\Laravel\Authorization\Exceptions\SystemRoleProtectedException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\SystemRoleGuard;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\CatchesRefusals;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `SystemRoleGuard`: the events of a grant service write,
 * dispatched through the system protection of a role that is the grantee.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SystemRoleGuard::class)]
final class SystemRoleGuardTest extends TestCase
{
    use CatchesRefusals;

    /**
     * A write to an identity is dispatched as it is, even when its key is also
     * a system role's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWriteToAnIdentityIsNotGuarded(): void
    {
        $role     = self::systemRole();
        $identity = StubIdentity::query()->create(['id' => $role->id]);
        $event    = self::event($role);

        Event::fake([PermissionGranted::class, SystemOverrideUsed::class]);

        SystemRoleGuard::dispatch(GrantTarget::POLICY, $identity, null, $event);
        SystemRoleGuard::dispatch(GrantTarget::POLICY, Reference::of($identity), null, $event);

        Event::assertDispatchedTimes(PermissionGranted::class, 2);
        Event::assertNotDispatched(SystemOverrideUsed::class);
    }

    /**
     * A trusted write to a role given as a model is guarded on that model, so
     * the override it carries unlocks the change, reported as a change of the
     * kind written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATrustedWriteUsesTheOverrideOnTheRoleGiven(): void
    {
        $role = self::systemRole();

        Event::fake([PermissionGranted::class, SystemOverrideUsed::class]);

        SystemRoleGuard::dispatch(GrantTarget::POLICY, $role->forceSystem(), null, self::event($role));

        Event::assertDispatchedTimes(PermissionGranted::class, 1);
        Event::assertDispatched(SystemOverrideUsed::class, static fn (SystemOverrideUsed $event): bool => $event->protectedOperation === 'policy-change');
    }

    /**
     * A delegated write, or one to a role named by a reference, is guarded on
     * the role as stored, so the override on the role given never reaches it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedOrReferencedWriteGuardsTheRoleAsStored(): void
    {
        $role  = self::systemRole();
        $actor = ActingContext::for(StubIdentity::query()->create(['id' => 'admin-1']));

        Event::fake([PermissionGranted::class, SystemOverrideUsed::class]);

        $refusals = [
            self::refusalOf(static fn () => SystemRoleGuard::dispatch(GrantTarget::PERMISSION, $role->forceSystem(), $actor, self::event($role))),
            self::refusalOf(static fn () => SystemRoleGuard::dispatch(GrantTarget::PERMISSION, Reference::of($role->forceSystem()), null, self::event($role))),
        ];

        foreach ($refusals as $refusal) {
            self::assertInstanceOf(SystemRoleProtectedException::class, $refusal);
            self::assertSame('permission-change', $refusal->getOperation());
        }

        Event::assertNothingDispatched();
    }

    /**
     * A reference to a role that does not exist names no role to guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReferenceToNoRoleIsNotGuarded(): void
    {
        $role = self::systemRole();

        Event::fake([PermissionGranted::class]);

        SystemRoleGuard::dispatch(GrantTarget::POLICY, new Reference($role->getMorphClass(), (string) Str::uuid()), null, self::event($role));

        Event::assertDispatchedTimes(PermissionGranted::class, 1);
    }

    /**
     * Create a platform system role.
     *
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function systemRole(): Role
    {
        return Role::query()->create(['name' => 'admin', 'is_system' => true]);
    }

    /**
     * Build the event of a grant of a permission to the role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return \SineMacula\Laravel\Authorization\Events\Role\PermissionGranted
     */
    private static function event(Role $role): PermissionGranted
    {
        return new PermissionGranted(Operation::begin(), Reference::of($role), $role->name, new Reference('permission', '1'), 'posts:read', null, null);
    }
}
