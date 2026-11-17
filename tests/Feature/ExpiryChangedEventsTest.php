<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\HasPermissions;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Concerns\HasRoles;
use SineMacula\Laravel\Authorization\Events\Grantee\PermissionExpiryChanged as GranteePermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Grantee\PermissionGranted as GranteePermissionGranted;
use SineMacula\Laravel\Authorization\Events\Grantee\PolicyAttached as GranteePolicyAttached;
use SineMacula\Laravel\Authorization\Events\Grantee\PolicyExpiryChanged as GranteePolicyExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Grantee\RoleAssigned as GranteeRoleAssigned;
use SineMacula\Laravel\Authorization\Events\Grantee\RoleExpiryChanged as GranteeRoleExpiryChanged;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\StubGrantee;
use Tests\TestCase;

/**
 * Feature coverage for the expiry-changed event family.
 *
 * Calling `assignRole()` / `givePermission()` / `attachPolicy()` again for a
 * held grant with a different expiry, or for one that has expired, rewrites the
 * grant's `expires_at` through the grant service. The expiry-changed events
 * give audit consumers a distinct signal for that rewrite, dispatched alongside
 * the `Assigned` / `Granted` / `Attached` event. A fresh grant dispatches only
 * the `Assigned` / `Granted` / `Attached` event.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GranteeRoleExpiryChanged::class)]
#[CoversClass(GranteePermissionExpiryChanged::class)]
#[CoversClass(GranteePolicyExpiryChanged::class)]
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
     * Reset the Carbon test now between tests so wall-clock travel never leaks
     * across scenarios.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Re-assigning a forever role grant with an expiry shortens it and fires
     * `GranteeRoleExpiryChanged` alongside the usual `GranteeRoleAssigned`.
     *
     * @return void
     */
    public function testShorteningForeverRoleGrantFiresExpiryChanged(): void
    {
        Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'oncall',
            'guard' => 'web',
        ]);

        $user = StubGrantee::create(['id' => (string) Str::uuid()]);
        $user->assignRole('oncall');

        Event::fake([GranteeRoleAssigned::class, GranteeRoleExpiryChanged::class]);

        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->assignRole('oncall', expiresAt: $expires);

        Event::assertDispatched(GranteeRoleAssigned::class);
        Event::assertDispatched(
            GranteeRoleExpiryChanged::class,
            static fn (GranteeRoleExpiryChanged $e): bool => $e->previousExpiresAt === null
                && $e->expiresAt instanceof \DateTimeInterface
                && $e->expiresAt->getTimestamp() === $expires->getTimestamp(),
        );
    }

    /**
     * Re-assigning an expiring role grant with a null expiry extends it to
     * forever and fires the expiry-changed event.
     *
     * @return void
     */
    public function testExtendingExpiringRoleGrantToForeverFiresExpiryChanged(): void
    {
        Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'oncall',
            'guard' => 'web',
        ]);

        $user    = StubGrantee::create(['id' => (string) Str::uuid()]);
        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->assignRole('oncall', expiresAt: $expires);

        Event::fake([GranteeRoleExpiryChanged::class]);

        $user->assignRole('oncall');

        Event::assertDispatched(
            GranteeRoleExpiryChanged::class,
            static fn (GranteeRoleExpiryChanged $e): bool => $e->previousExpiresAt instanceof \DateTimeInterface
                && $e->previousExpiresAt->getTimestamp() === $expires->getTimestamp()
                && $e->expiresAt                         === null,
        );
    }

    /**
     * Re-assigning a role with the same expiry value fires no expiry-changed
     * event.
     *
     * @return void
     */
    public function testRoleReassignmentWithSameExpiryDoesNotFireExpiryChanged(): void
    {
        Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'oncall',
            'guard' => 'web',
        ]);

        $user    = StubGrantee::create(['id' => (string) Str::uuid()]);
        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->assignRole('oncall', expiresAt: $expires);

        Event::fake([GranteeRoleExpiryChanged::class]);

        $user->assignRole('oncall', expiresAt: $expires);

        Event::assertNotDispatched(GranteeRoleExpiryChanged::class);
    }

    /**
     * A fresh role grant fires only `GranteeRoleAssigned` — the expiry-changed
     * event is reserved for mutations of an existing pivot row.
     *
     * @return void
     */
    public function testFreshRoleGrantDoesNotFireExpiryChanged(): void
    {
        Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'oncall',
            'guard' => 'web',
        ]);

        $user = StubGrantee::create(['id' => (string) Str::uuid()]);

        Event::fake([GranteeRoleAssigned::class, GranteeRoleExpiryChanged::class]);

        $user->assignRole('oncall', expiresAt: Carbon::parse(self::EXPIRY_INSTANT));

        Event::assertDispatched(GranteeRoleAssigned::class);
        Event::assertNotDispatched(GranteeRoleExpiryChanged::class);
    }

    /**
     * Re-granting a forever permission with an expiry shortens it and fires
     * `GranteePermissionExpiryChanged`.
     *
     * @return void
     */
    public function testShorteningForeverPermissionGrantFiresExpiryChanged(): void
    {
        Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::PERMISSION_NAME,
            'guard' => 'web',
        ]);

        $user = StubGrantee::create(['id' => (string) Str::uuid()]);
        $user->givePermission(self::PERMISSION_NAME);

        Event::fake([GranteePermissionGranted::class, GranteePermissionExpiryChanged::class]);

        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->givePermission(self::PERMISSION_NAME, expiresAt: $expires);

        Event::assertDispatched(GranteePermissionGranted::class);
        Event::assertDispatched(
            GranteePermissionExpiryChanged::class,
            static fn (GranteePermissionExpiryChanged $e): bool => $e->previousExpiresAt === null
                && $e->expiresAt instanceof \DateTimeInterface
                && $e->expiresAt->getTimestamp() === $expires->getTimestamp(),
        );
    }

    /**
     * Re-granting an expiring permission with a null expiry extends it to
     * forever and fires the expiry-changed event.
     *
     * @return void
     */
    public function testExtendingExpiringPermissionGrantToForeverFiresExpiryChanged(): void
    {
        Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::PERMISSION_NAME,
            'guard' => 'web',
        ]);

        $user    = StubGrantee::create(['id' => (string) Str::uuid()]);
        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->givePermission(self::PERMISSION_NAME, expiresAt: $expires);

        Event::fake([GranteePermissionExpiryChanged::class]);

        $user->givePermission(self::PERMISSION_NAME);

        Event::assertDispatched(
            GranteePermissionExpiryChanged::class,
            static fn (GranteePermissionExpiryChanged $e): bool => $e->previousExpiresAt instanceof \DateTimeInterface
                && $e->previousExpiresAt->getTimestamp() === $expires->getTimestamp()
                && $e->expiresAt                         === null,
        );
    }

    /**
     * Re-granting a permission with the same expiry value fires no
     * expiry-changed event.
     *
     * @return void
     */
    public function testPermissionRegrantWithSameExpiryDoesNotFireExpiryChanged(): void
    {
        Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => self::PERMISSION_NAME,
            'guard' => 'web',
        ]);

        $user    = StubGrantee::create(['id' => (string) Str::uuid()]);
        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->givePermission(self::PERMISSION_NAME, expiresAt: $expires);

        Event::fake([GranteePermissionExpiryChanged::class]);

        $user->givePermission(self::PERMISSION_NAME, expiresAt: $expires);

        Event::assertNotDispatched(GranteePermissionExpiryChanged::class);
    }

    /**
     * Re-attaching a forever policy with an expiry shortens it and fires
     * `GranteePolicyExpiryChanged`.
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

        $user = StubGrantee::create(['id' => (string) Str::uuid()]);
        $user->attachPolicy($policy);

        Event::fake([GranteePolicyAttached::class, GranteePolicyExpiryChanged::class]);

        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->attachPolicy($policy, expiresAt: $expires);

        Event::assertDispatched(GranteePolicyAttached::class);
        Event::assertDispatched(
            GranteePolicyExpiryChanged::class,
            static fn (GranteePolicyExpiryChanged $e): bool => $e->previousExpiresAt === null
                && $e->expiresAt instanceof \DateTimeInterface
                && $e->expiresAt->getTimestamp() === $expires->getTimestamp(),
        );
    }

    /**
     * Re-attaching an expiring policy with a null expiry extends it to forever
     * and fires the expiry-changed event.
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

        $user    = StubGrantee::create(['id' => (string) Str::uuid()]);
        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->attachPolicy($policy, expiresAt: $expires);

        Event::fake([GranteePolicyExpiryChanged::class]);

        $user->attachPolicy($policy);

        Event::assertDispatched(
            GranteePolicyExpiryChanged::class,
            static fn (GranteePolicyExpiryChanged $e): bool => $e->previousExpiresAt instanceof \DateTimeInterface
                && $e->previousExpiresAt->getTimestamp() === $expires->getTimestamp()
                && $e->expiresAt                         === null,
        );
    }

    /**
     * Re-attaching a policy with the same expiry value fires no expiry-changed
     * event.
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

        $user    = StubGrantee::create(['id' => (string) Str::uuid()]);
        $expires = Carbon::parse(self::EXPIRY_INSTANT);
        $user->attachPolicy($policy, expiresAt: $expires);

        Event::fake([GranteePolicyExpiryChanged::class]);

        $user->attachPolicy($policy, expiresAt: $expires);

        Event::assertNotDispatched(GranteePolicyExpiryChanged::class);
    }

    /**
     * A fresh policy attachment fires only `GranteePolicyAttached` — the
     * expiry-changed event is reserved for mutations of an existing pivot row.
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

        $user = StubGrantee::create(['id' => (string) Str::uuid()]);

        Event::fake([GranteePolicyAttached::class, GranteePolicyExpiryChanged::class]);

        $user->attachPolicy($policy, expiresAt: Carbon::parse(self::EXPIRY_INSTANT));

        Event::assertDispatched(GranteePolicyAttached::class);
        Event::assertNotDispatched(GranteePolicyExpiryChanged::class);
    }
}
