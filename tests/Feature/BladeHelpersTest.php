<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Container\Container;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\BladeHelpers;
use Tests\Concerns\ChecksAccess;
use Tests\Concerns\RefusesThePackage;
use Tests\Feature\Stubs\AuthenticatableIdentity;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\RolesOnlyPrincipal;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Feature\Stubs\SuspendableIdentity;
use Tests\TestCase;

/**
 * Feature coverage for the helpers the shipped Blade directives compile into:
 * the permission helpers decide through the full decision, the role helpers
 * check role membership, both on the subject the subject resolver returns (with
 * the shipped resolver, the user Laravel signed in).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(BladeHelpers::class)]
final class BladeHelpersTest extends TestCase
{
    use ChecksAccess, RefusesThePackage;

    /**
     * The role helpers count the roles the subject's identity holds, and none
     * while the subject is inactive.
     *
     * @return void
     */
    public function testTheRoleHelpersCountTheIdentityUnlessInactive(): void
    {
        $principal = SuspendableIdentity::create(['id' => 'account-1']);
        $identity  = StubSecondIdentity::create(['id' => 'person-1']);

        $principal->assignRole(Role::create(['name' => 'editor']));
        $identity->assignRole(Role::create(['name' => 'staff']));
        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver(new Subject($principal, $identity)));

        self::assertTrue(BladeHelpers::hasRole('staff'));
        self::assertTrue(BladeHelpers::hasAllRoles(['editor', 'staff']));
        self::assertFalse(BladeHelpers::hasAllRoles(['editor', 'owner']));

        $principal->suspended = true;

        self::assertFalse(BladeHelpers::hasRole('staff'));
        self::assertFalse(BladeHelpers::hasAllRoles(['editor', 'staff']));
    }

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

        self::assertSame($user, BladeHelpers::currentSubject()?->subject);
        self::assertTrue(BladeHelpers::hasRole('admin'));
        self::assertTrue(BladeHelpers::hasAllRoles(['admin']));
        self::assertFalse(BladeHelpers::hasRole('auditor'));
        self::assertTrue(BladeHelpers::hasPermission('posts:create'));
        self::assertTrue(BladeHelpers::hasAllPermissions(['posts:create']));
        self::assertFalse(BladeHelpers::hasPermission('posts:delete'));
    }

    /**
     * Without the package's manager in the container there is no subject, and
     * every helper is false.
     *
     * @return void
     */
    public function testWithoutTheManagerEveryHelperIsFalse(): void
    {
        $previous = Container::getInstance();

        Container::setInstance(new Container);

        try {
            self::assertNull(BladeHelpers::currentSubject());
            self::assertFalse(BladeHelpers::hasRole('admin'));
            self::assertFalse(BladeHelpers::hasAllRoles('admin'));
            self::assertFalse(BladeHelpers::hasPermission('posts:create'));
            self::assertFalse(BladeHelpers::hasAllPermissions('posts:create'));
        } finally {
            Container::setInstance($previous);
        }
    }

    /**
     * An explicit deny wins over a held permission, and a policy allow allows
     * without one, for both permission helpers.
     *
     * @return void
     */
    public function testPermissionsAreDecidedOnTheFullDecision(): void
    {
        $identity = self::identityHolding(permissions: ['posts:create', 'posts:delete']);
        self::attachStatement($identity, 'deny', ['posts:delete']);
        self::attachStatement($identity, 'allow', ['posts:publish']);

        $this->actAs($identity);

        self::assertFalse(BladeHelpers::hasPermission('posts:delete'));
        self::assertFalse(BladeHelpers::hasAllPermissions(['posts:create', 'posts:delete']));
        self::assertTrue(BladeHelpers::hasPermission('posts:publish'));
        self::assertTrue(BladeHelpers::hasAllPermissions(['posts:create', 'posts:publish']));
    }

    /**
     * `|` splits every entry of a string or a list, for the any and the all
     * helpers alike, with whitespace and empty names ignored.
     *
     * @return void
     */
    public function testPipesSplitEveryEntry(): void
    {
        $this->actAs(self::identityHolding(['admin', 'editor'], ['posts:create', 'posts:update']));

        self::assertTrue(BladeHelpers::hasRole('auditor|admin'));
        self::assertTrue(BladeHelpers::hasRole(['auditor | editor']));
        self::assertTrue(BladeHelpers::hasAllRoles('admin|editor'));
        self::assertTrue(BladeHelpers::hasAllRoles(['admin | ', 'editor']));
        self::assertFalse(BladeHelpers::hasAllRoles(['admin|auditor']));
        self::assertTrue(BladeHelpers::hasPermission('posts:delete|posts:update'));
        self::assertTrue(BladeHelpers::hasPermission(['posts:delete | posts:create']));
        self::assertTrue(BladeHelpers::hasAllPermissions('posts:create|posts:update'));
        self::assertFalse(BladeHelpers::hasAllPermissions(['posts:create|posts:delete']));
    }

    /**
     * A list naming nothing is false, even for a subject allowed everything.
     *
     * @return void
     */
    public function testAListNamingNothingIsFalse(): void
    {
        $this->allowEverySubject(['*']);
        $this->actAs(self::identityHolding(['admin']));

        self::assertFalse(BladeHelpers::hasRole(' | '));
        self::assertFalse(BladeHelpers::hasAllRoles(''));
        self::assertFalse(BladeHelpers::hasPermission([]));
        self::assertFalse(BladeHelpers::hasAllPermissions(' | '));
    }

    /**
     * A role helper honours a guard: only roles of that guard or of no guard
     * count.
     *
     * @return void
     */
    public function testRoleHelpersHonourAGuard(): void
    {
        config(['auth.guards.api' => ['driver' => 'session', 'provider' => 'users']]);

        $identity = StubIdentity::create(['id' => 'guarded']);
        $identity->assignRole(Role::create(['name' => 'admin', 'guard' => 'api']));
        $identity->assignRole(Role::create(['name' => 'auditor', 'guard' => null]));

        $this->actAs($identity);

        self::assertTrue(BladeHelpers::hasRole('admin', 'api'));
        self::assertFalse(BladeHelpers::hasRole('admin', 'web'));
        self::assertTrue(BladeHelpers::hasAllRoles('admin|auditor', 'api'));
        self::assertFalse(BladeHelpers::hasAllRoles('admin|auditor', 'web'));
        self::assertTrue(BladeHelpers::hasAllRoles('auditor', 'web'));
    }

    /**
     * A role helper refuses a guard that is not an authentication guard.
     *
     * @return void
     */
    public function testRoleHelpersRefuseAnUnknownGuard(): void
    {
        $this->expectException(InvalidCheckArgumentException::class);
        $this->expectExceptionMessage('\'editor\' is not an authentication guard.');

        BladeHelpers::hasAllRoles('admin', 'editor');
    }

    /**
     * The any-role helper refuses an unknown guard too.
     *
     * @return void
     */
    public function testTheAnyRoleHelperRefusesAnUnknownGuard(): void
    {
        $this->expectException(InvalidCheckArgumentException::class);

        BladeHelpers::hasRole('admin', 'editor');
    }

    /**
     * A permission helper refuses any guard.
     *
     * @return void
     */
    public function testPermissionHelpersRefuseAGuard(): void
    {
        $this->expectException(InvalidCheckArgumentException::class);
        $this->expectExceptionMessage('A permission check takes no guard');

        BladeHelpers::hasPermission('posts:create', 'web');
    }

    /**
     * The all-permissions helper refuses any guard too.
     *
     * @return void
     */
    public function testTheAllPermissionsHelperRefusesAGuard(): void
    {
        $this->expectException(InvalidCheckArgumentException::class);

        BladeHelpers::hasAllPermissions('posts:create', 'web');
    }

    /**
     * A subject that can hold roles but not permissions has its roles checked
     * and its actions decided, here by a policy every subject is given; a
     * subject that cannot hold roles holds none.
     *
     * @return void
     */
    public function testAnySubjectTheManagerDecidesAboutIsAccepted(): void
    {
        $this->allowEverySubject(['posts:create']);
        $this->actAs(new RolesOnlyPrincipal);

        self::assertTrue(BladeHelpers::hasAllRoles(['editor']));
        self::assertFalse(BladeHelpers::hasAllRoles(['editor', 'admin']));
        self::assertTrue(BladeHelpers::hasPermission(['posts:create']));
        self::assertTrue(BladeHelpers::hasAllPermissions(['posts:create']));
        self::assertFalse(BladeHelpers::hasAllPermissions(['posts:create', 'posts:delete']));

        $this->actAs(new \stdClass);

        self::assertFalse(BladeHelpers::hasRole('editor'));
        self::assertFalse(BladeHelpers::hasAllRoles('editor'));
        self::assertTrue(BladeHelpers::hasPermission('posts:create'));
    }

    /**
     * The permission helpers and the Gate answer the same.
     *
     * @return void
     */
    public function testThePermissionHelpersAndTheGateAgree(): void
    {
        $this->declarePermissionEnum();

        $identity = self::identityHolding(permissions: ['posts:create', 'posts:delete']);
        self::attachStatement($identity, 'deny', ['posts:delete']);

        $this->actAs($identity);

        foreach (['posts:create' => true, 'posts:delete' => false] as $action => $expected) {
            self::assertSame($expected, Gate::forUser($identity)->allows($action));
            self::assertSame($expected, BladeHelpers::hasPermission($action));
        }
    }

    /**
     * Once the package refuses, every Blade helper refuses by its own guard,
     * reading nothing.
     *
     * @return void
     */
    public function testEveryHelperRefusesOnceThePackageRefuses(): void
    {
        $this->refuseThePackage();

        $this->assertEachRefused([
            'currentSubject'    => BladeHelpers::currentSubject(...),
            'hasRole'           => static fn () => BladeHelpers::hasRole('editor'),
            'hasAllRoles'       => static fn () => BladeHelpers::hasAllRoles(['editor']),
            'hasPermission'     => static fn () => BladeHelpers::hasPermission(['posts:read']),
            'hasAllPermissions' => static fn () => BladeHelpers::hasAllPermissions(['posts:read']),
        ]);
    }

    /**
     * Create a user holding the `admin` role and the `posts:create` permission.
     *
     * @return \Tests\Feature\Stubs\AuthenticatableIdentity
     */
    private function seedGrantedUser(): AuthenticatableIdentity
    {
        $user = AuthenticatableIdentity::create(['id' => 'signed-in']);
        $user->assignRole(Role::create(['name' => 'admin', 'guard' => 'web']));
        $user->givePermission(Permission::create(['name' => 'posts:create', 'guard' => 'web']));

        return $user;
    }
}
