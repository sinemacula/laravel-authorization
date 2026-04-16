<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Events\IdentityPermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\IdentityPermissionGranted;
use SineMacula\Laravel\Authorization\Events\IdentityPolicyAttached;
use SineMacula\Laravel\Authorization\Events\IdentityPolicyExpiryChanged;
use SineMacula\Laravel\Authorization\Events\IdentityRoleAssigned;
use SineMacula\Laravel\Authorization\Events\IdentityRoleExpiryChanged;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Traits\HasPermissions;
use SineMacula\Laravel\Authorization\Traits\HasPolicies;
use SineMacula\Laravel\Authorization\Traits\HasRoles;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature coverage for the expiry-changed event family
 * (issue #80).
 *
 * `assignRole()` / `givePermission()` / `attachPolicy()` write
 * through `syncWithoutDetaching` and so silently overwrite an
 * existing pivot row's `expires_at`. The expiry-changed events
 * give audit consumers a distinct signal for the case where the
 * pre-write `expires_at` differs from the supplied value, fired
 * alongside the existing `Assigned` / `Granted` / `Attached`
 * event. A fresh grant fires only the `Assigned` / `Granted` /
 * `Attached` event.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentityRoleExpiryChanged::class)]
#[CoversClass(IdentityPermissionExpiryChanged::class)]
#[CoversClass(IdentityPolicyExpiryChanged::class)]
#[CoversTrait(HasRoles::class)]
#[CoversTrait(HasPermissions::class)]
#[CoversTrait(HasPolicies::class)]
final class ExpiryChangedEventsTest extends TestCase
{
    /** Canonical instant used as the temporal-grant expiry across every scenario. */
    private const string EXPIRY_INSTANT = '2026-12-01 12:00:00';

    /** Canonical permission name used across the permission expiry scenarios. */
    private const string PERMISSION_NAME = 'emergency:publish';

    /** Canonical action used inside the policy fixture documents. */
    private const string POLICY_ACTION = 'systems:override';

    /**
     * Reset the Carbon test now between tests so wall-clock
     * travel never leaks across scenarios.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Re-assigning a forever role grant with an expiry shortens
     * it and fires `IdentityRoleExpiryChanged` alongside the
     * usual `IdentityRoleAssigned`.
     *
     * @return void
     */
    public function testShorteningForeverRoleGrantFiresExpiryChanged(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'oncall',
            'guard_name' => 'web',
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole('oncall');

        Event::fake([IdentityRoleAssigned::class, IdentityRoleExpiryChanged::class]);

        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->assignRole('oncall', expiresAt: $expires);

        Event::assertDispatched(IdentityRoleAssigned::class);
        Event::assertDispatched(
            IdentityRoleExpiryChanged::class,
            static fn (IdentityRoleExpiryChanged $e): bool => $e->previousExpiresAt === null
                && $e->newExpiresAt instanceof \DateTimeInterface
                && $e->newExpiresAt->getTimestamp() === $expires->getTimestamp(),
        );
    }

    /**
     * Re-assigning an expiring role grant with a null expiry
     * extends it to forever and fires the expiry-changed event.
     *
     * @return void
     */
    public function testExtendingExpiringRoleGrantToForeverFiresExpiryChanged(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'oncall',
            'guard_name' => 'web',
        ]);

        $user    = StubIdentity::create(['id' => (string) Str::uuid()]);
        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->assignRole('oncall', expiresAt: $expires);

        Event::fake([IdentityRoleExpiryChanged::class]);

        $user->assignRole('oncall');

        Event::assertDispatched(
            IdentityRoleExpiryChanged::class,
            static fn (IdentityRoleExpiryChanged $e): bool => $e->previousExpiresAt instanceof \DateTimeInterface
                && $e->previousExpiresAt->getTimestamp() === $expires->getTimestamp()
                && $e->newExpiresAt                      === null,
        );
    }

    /**
     * Re-assigning a role with the same expiry value fires no
     * expiry-changed event.
     *
     * @return void
     */
    public function testRoleReassignmentWithSameExpiryDoesNotFireExpiryChanged(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'oncall',
            'guard_name' => 'web',
        ]);

        $user    = StubIdentity::create(['id' => (string) Str::uuid()]);
        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->assignRole('oncall', expiresAt: $expires);

        Event::fake([IdentityRoleExpiryChanged::class]);

        $user->assignRole('oncall', expiresAt: $expires);

        Event::assertNotDispatched(IdentityRoleExpiryChanged::class);
    }

    /**
     * A fresh role grant fires only `IdentityRoleAssigned` —
     * the expiry-changed event is reserved for mutations of an
     * existing pivot row.
     *
     * @return void
     */
    public function testFreshRoleGrantDoesNotFireExpiryChanged(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'oncall',
            'guard_name' => 'web',
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        Event::fake([IdentityRoleAssigned::class, IdentityRoleExpiryChanged::class]);

        $user->assignRole('oncall', expiresAt: Carbon::parse(self::EXPIRY_INSTANT));

        Event::assertDispatched(IdentityRoleAssigned::class);
        Event::assertNotDispatched(IdentityRoleExpiryChanged::class);
    }

    /**
     * Re-granting a forever permission with an expiry shortens
     * it and fires `IdentityPermissionExpiryChanged`.
     *
     * @return void
     */
    public function testShorteningForeverPermissionGrantFiresExpiryChanged(): void
    {
        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => self::PERMISSION_NAME,
            'guard_name' => 'web',
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission(self::PERMISSION_NAME);

        Event::fake([IdentityPermissionGranted::class, IdentityPermissionExpiryChanged::class]);

        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->givePermission(self::PERMISSION_NAME, expiresAt: $expires);

        Event::assertDispatched(IdentityPermissionGranted::class);
        Event::assertDispatched(
            IdentityPermissionExpiryChanged::class,
            static fn (IdentityPermissionExpiryChanged $e): bool => $e->previousExpiresAt === null
                && $e->newExpiresAt instanceof \DateTimeInterface
                && $e->newExpiresAt->getTimestamp() === $expires->getTimestamp(),
        );
    }

    /**
     * Re-granting an expiring permission with a null expiry
     * extends it to forever and fires the expiry-changed event.
     *
     * @return void
     */
    public function testExtendingExpiringPermissionGrantToForeverFiresExpiryChanged(): void
    {
        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => self::PERMISSION_NAME,
            'guard_name' => 'web',
        ]);

        $user    = StubIdentity::create(['id' => (string) Str::uuid()]);
        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->givePermission(self::PERMISSION_NAME, expiresAt: $expires);

        Event::fake([IdentityPermissionExpiryChanged::class]);

        $user->givePermission(self::PERMISSION_NAME);

        Event::assertDispatched(
            IdentityPermissionExpiryChanged::class,
            static fn (IdentityPermissionExpiryChanged $e): bool => $e->previousExpiresAt instanceof \DateTimeInterface
                && $e->previousExpiresAt->getTimestamp() === $expires->getTimestamp()
                && $e->newExpiresAt                      === null,
        );
    }

    /**
     * Re-granting a permission with the same expiry value fires
     * no expiry-changed event.
     *
     * @return void
     */
    public function testPermissionRegrantWithSameExpiryDoesNotFireExpiryChanged(): void
    {
        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => self::PERMISSION_NAME,
            'guard_name' => 'web',
        ]);

        $user    = StubIdentity::create(['id' => (string) Str::uuid()]);
        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->givePermission(self::PERMISSION_NAME, expiresAt: $expires);

        Event::fake([IdentityPermissionExpiryChanged::class]);

        $user->givePermission(self::PERMISSION_NAME, expiresAt: $expires);

        Event::assertNotDispatched(IdentityPermissionExpiryChanged::class);
    }

    /**
     * Re-attaching a forever policy with an expiry shortens it
     * and fires `IdentityPolicyExpiryChanged`.
     *
     * @return void
     */
    public function testShorteningForeverPolicyAttachmentFiresExpiryChanged(): void
    {
        $policy = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'break-glass',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => [self::POLICY_ACTION]]]],
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->attachPolicy($policy);

        Event::fake([IdentityPolicyAttached::class, IdentityPolicyExpiryChanged::class]);

        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->attachPolicy($policy, expiresAt: $expires);

        Event::assertDispatched(IdentityPolicyAttached::class);
        Event::assertDispatched(
            IdentityPolicyExpiryChanged::class,
            static fn (IdentityPolicyExpiryChanged $e): bool => $e->previousExpiresAt === null
                && $e->newExpiresAt instanceof \DateTimeInterface
                && $e->newExpiresAt->getTimestamp() === $expires->getTimestamp(),
        );
    }

    /**
     * Re-attaching an expiring policy with a null expiry extends
     * it to forever and fires the expiry-changed event.
     *
     * @return void
     */
    public function testExtendingExpiringPolicyAttachmentToForeverFiresExpiryChanged(): void
    {
        $policy = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'break-glass',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => [self::POLICY_ACTION]]]],
        ]);

        $user    = StubIdentity::create(['id' => (string) Str::uuid()]);
        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->attachPolicy($policy, expiresAt: $expires);

        Event::fake([IdentityPolicyExpiryChanged::class]);

        $user->attachPolicy($policy);

        Event::assertDispatched(
            IdentityPolicyExpiryChanged::class,
            static fn (IdentityPolicyExpiryChanged $e): bool => $e->previousExpiresAt instanceof \DateTimeInterface
                && $e->previousExpiresAt->getTimestamp() === $expires->getTimestamp()
                && $e->newExpiresAt                      === null,
        );
    }

    /**
     * Re-attaching a policy with the same expiry value fires no
     * expiry-changed event.
     *
     * @return void
     */
    public function testPolicyReattachmentWithSameExpiryDoesNotFireExpiryChanged(): void
    {
        $policy = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'break-glass',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => [self::POLICY_ACTION]]]],
        ]);

        $user    = StubIdentity::create(['id' => (string) Str::uuid()]);
        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->attachPolicy($policy, expiresAt: $expires);

        Event::fake([IdentityPolicyExpiryChanged::class]);

        $user->attachPolicy($policy, expiresAt: $expires);

        Event::assertNotDispatched(IdentityPolicyExpiryChanged::class);
    }

    /**
     * A fresh policy attachment fires only
     * `IdentityPolicyAttached` — the expiry-changed event is
     * reserved for mutations of an existing pivot row.
     *
     * @return void
     */
    public function testFreshPolicyAttachmentDoesNotFireExpiryChanged(): void
    {
        $policy = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'break-glass',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => [self::POLICY_ACTION]]]],
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        Event::fake([IdentityPolicyAttached::class, IdentityPolicyExpiryChanged::class]);

        $user->attachPolicy($policy, expiresAt: Carbon::parse(self::EXPIRY_INSTANT));

        Event::assertDispatched(IdentityPolicyAttached::class);
        Event::assertNotDispatched(IdentityPolicyExpiryChanged::class);
    }
}
