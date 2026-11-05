<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Container\Container;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\BladeHelpers;
use Tests\Feature\Stubs\AuthenticatableIdentity;
use Tests\TestCase;

/**
 * Feature coverage for the subject the shipped Blade helpers check: the one the
 * subject resolver returns, which with the shipped resolver is the user Laravel
 * signed in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BladeHelpers::class)]
final class BladeHelpersTest extends TestCase
{
    /**
     * With no user signed in there is no subject, and every helper is false.
     *
     * @return void
     */
    public function testNoSignedInUserMeansNoSubject(): void
    {
        $this->seedGrantedUser();

        self::assertNull(BladeHelpers::currentSubject());
        self::assertFalse(BladeHelpers::hasRole('admin'));
        self::assertFalse(BladeHelpers::hasAllRoles(['admin']));
        self::assertFalse(BladeHelpers::hasPermission('posts:create'));
        self::assertFalse(BladeHelpers::hasAllPermissions(['posts:create']));
    }

    /**
     * The user Laravel signed in is the subject the helpers check, with no
     * resolver of the application's own.
     *
     * @return void
     */
    public function testTheSignedInUserIsTheSubject(): void
    {
        $user = $this->seedGrantedUser();

        $this->actingAs($user);

        self::assertSame($user, BladeHelpers::currentSubject());
        self::assertTrue(BladeHelpers::hasRole('admin'));
        self::assertTrue(BladeHelpers::hasAllRoles(['admin']));
        self::assertFalse(BladeHelpers::hasRole('auditor'));
        self::assertTrue(BladeHelpers::hasPermission('posts:create'));
        self::assertTrue(BladeHelpers::hasAllPermissions(['posts:create']));
        self::assertFalse(BladeHelpers::hasPermission('posts:delete'));
    }

    /**
     * Without the package's manager in the container there is no subject.
     *
     * @return void
     */
    public function testWithoutTheManagerThereIsNoSubject(): void
    {
        $previous = Container::getInstance();

        Container::setInstance(new Container);

        try {
            self::assertNull(BladeHelpers::currentSubject());
        } finally {
            Container::setInstance($previous);
        }
    }

    /**
     * Create a user holding the `admin` role and the `posts:create` permission.
     *
     * @return \Tests\Feature\Stubs\AuthenticatableIdentity
     */
    private function seedGrantedUser(): AuthenticatableIdentity
    {
        Role::create(['id' => (string) Str::uuid(), 'name' => 'admin', 'guard' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:create', 'guard' => 'web']);

        $user = AuthenticatableIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole('admin');
        $user->givePermission('posts:create');

        return $user;
    }
}
