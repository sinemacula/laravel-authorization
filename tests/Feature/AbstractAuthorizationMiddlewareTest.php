<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Http\Middleware\AbstractAuthorizationMiddleware;
use SineMacula\Laravel\Authorization\Http\Middleware\RequirePermission;
use SineMacula\Laravel\Authorization\Http\Middleware\RequireRole;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Tests\Feature\Stubs\AuthenticatableIdentity;
use Tests\TestCase;

/**
 * Feature coverage for the subject the shipped `role` and `permission`
 * middleware check: the one the subject resolver returns, which with the
 * shipped resolver is the user Laravel signed in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractAuthorizationMiddleware::class)]
#[CoversClass(RequireRole::class)]
#[CoversClass(RequirePermission::class)]
final class AbstractAuthorizationMiddlewareTest extends TestCase
{
    /**
     * With no user signed in there is no subject, and the role middleware
     * answers unauthenticated.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function testRoleMiddlewareWithoutASignedInUserIsUnauthenticated(): void
    {
        $this->seedGrantedUser();

        $this->expectException(AuthenticationException::class);

        (new RequireRole)->handle(Request::create('/test'), self::passThrough(), 'admin');
    }

    /**
     * With no user signed in there is no subject, and the permission middleware
     * answers unauthenticated.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function testPermissionMiddlewareWithoutASignedInUserIsUnauthenticated(): void
    {
        $this->seedGrantedUser();

        $this->expectException(AuthenticationException::class);

        (new RequirePermission)->handle(Request::create('/test'), self::passThrough(), 'posts:create');
    }

    /**
     * The user Laravel signed in passes the role and permission it holds, with
     * no resolver of the application's own.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function testTheSignedInUserPassesWhatItHolds(): void
    {
        $this->actingAs($this->seedGrantedUser());

        $role       = (new RequireRole)->handle(Request::create('/test'), self::passThrough(), 'admin');
        $permission = (new RequirePermission)->handle(Request::create('/test'), self::passThrough(), 'posts:create');

        self::assertInstanceOf(Response::class, $role);
        self::assertSame(200, $role->getStatusCode());
        self::assertInstanceOf(Response::class, $permission);
        self::assertSame(200, $permission->getStatusCode());
    }

    /**
     * The user Laravel signed in is refused a role it does not hold.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function testTheSignedInUserIsRefusedWhatItLacks(): void
    {
        $this->actingAs($this->seedGrantedUser());

        $this->expectException(AccessDeniedHttpException::class);
        $this->expectExceptionMessage('Role required.');

        (new RequireRole)->handle(Request::create('/test'), self::passThrough(), 'auditor');
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

    /**
     * A pass-through `$next` closure that proves the middleware forwarded the
     * request.
     *
     * @return \Closure(\Illuminate\Http\Request): \Illuminate\Http\Response
     */
    private static function passThrough(): \Closure
    {
        return static fn (): Response => new Response('ok', 200);
    }
}
