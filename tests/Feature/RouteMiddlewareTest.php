<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Router;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Http\Middleware\RequirePermission;
use SineMacula\Laravel\Authorization\Http\Middleware\RequireRole;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Tests\Feature\Stubs\CustomRoleMiddlewareDouble;
use Tests\Feature\Stubs\StubAuthorizable;
use Tests\TestCase;

/**
 * Feature coverage for the shipped route middleware (issue #33).
 *
 * `RequireRole` / `RequirePermission` are exercised by constructing
 * a request, attaching a user resolver, and invoking the handle
 * method directly — this keeps the tests orthogonal to the Laravel
 * auth-provider plumbing Testbench would otherwise require. The
 * service-provider aliasing is covered separately via the router
 * binding.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequireRole::class)]
#[CoversClass(RequirePermission::class)]
#[CoversClass(AuthorizationServiceProvider::class)]
final class RouteMiddlewareTest extends TestCase
{
    /**
     * Permission string reused across the `permission` middleware
     * coverage. Deduplicated to a constant so the same literal does
     * not appear inline in eight places.
     *
     * @var string
     */
    private const string PERMISSION = 'posts:edit';

    /**
     * Unauthenticated requests raise `AuthenticationException` —
     * Laravel's exception handler renders that as a 401.
     *
     * @return void
     */
    public function testRoleMiddlewareRejectsUnauthenticatedRequest(): void
    {
        $middleware = new RequireRole;

        $this->expectException(AuthenticationException::class);
        $middleware->handle($this->requestAs(null), $this->passThrough(), 'admin');
    }

    /**
     * An authenticated identity that does not implement
     * `SupportsRoles` cannot answer role checks — the middleware
     * must fail closed with a 403, not let the request through.
     *
     * @return void
     */
    public function testRoleMiddlewareRejectsIdentityWithoutRoleSupport(): void
    {
        $middleware = new RequireRole;

        $this->expectException(AccessDeniedHttpException::class);
        $middleware->handle(
            $this->requestAs(new \stdClass),
            $this->passThrough(),
            'admin',
        );
    }

    /**
     * A user missing every required role is denied.
     *
     * @return void
     */
    public function testRoleMiddlewareDeniesWhenRoleMissing(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'editor',
            'guard_name' => 'web',
        ]);

        $user = StubAuthorizable::create(['id' => (string) Str::uuid()]);

        $middleware = new RequireRole;

        $this->expectException(AccessDeniedHttpException::class);
        $middleware->handle($this->requestAs($user), $this->passThrough(), 'admin');
    }

    /**
     * A user holding the required role is admitted.
     *
     * @return void
     */
    public function testRoleMiddlewareAdmitsWhenRolePresent(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'admin',
            'guard_name' => 'web',
        ]);

        $user = StubAuthorizable::create(['id' => (string) Str::uuid()]);
        $user->assignRole('admin');

        $response = (new RequireRole)->handle(
            $this->requestAs($user),
            $this->passThrough(),
            'admin',
        );

        self::assertInstanceOf(Response::class, $response);
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * Comma-separated role arguments (Laravel native) resolve to
     * OR semantics — holding either role is enough.
     *
     * @return void
     */
    public function testRoleMiddlewareHonoursCommaSeparatedOrSemantics(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'admin',
            'guard_name' => 'web',
        ]);
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'editor',
            'guard_name' => 'web',
        ]);

        $user = StubAuthorizable::create(['id' => (string) Str::uuid()]);
        $user->assignRole('editor');

        $response = (new RequireRole)->handle(
            $this->requestAs($user),
            $this->passThrough(),
            'admin',
            'editor',
        );

        self::assertInstanceOf(Response::class, $response);
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * Pipe-separated role arguments (Spatie convention) expand
     * identically to the comma form — holding either role suffices.
     *
     * @return void
     */
    public function testRoleMiddlewareHonoursPipeSeparatedOrSemantics(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'admin',
            'guard_name' => 'web',
        ]);
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'oncall',
            'guard_name' => 'web',
        ]);

        $user = StubAuthorizable::create(['id' => (string) Str::uuid()]);
        $user->assignRole('oncall');

        $response = (new RequireRole)->handle(
            $this->requestAs($user),
            $this->passThrough(),
            'admin|oncall',
        );

        self::assertInstanceOf(Response::class, $response);
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * Mixed separator forms are tolerated — a `pipe` inside one
     * argument and a `comma` across arguments should both expand.
     *
     * @return void
     */
    public function testRoleMiddlewareExpandsMixedSeparators(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'captain',
            'guard_name' => 'web',
        ]);

        $user = StubAuthorizable::create(['id' => (string) Str::uuid()]);
        $user->assignRole('captain');

        $response = (new RequireRole)->handle(
            $this->requestAs($user),
            $this->passThrough(),
            'admin|editor',
            'captain',
        );

        self::assertInstanceOf(Response::class, $response);
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * `RequirePermission` rejects unauthenticated requests the same
     * way `RequireRole` does.
     *
     * @return void
     */
    public function testPermissionMiddlewareRejectsUnauthenticatedRequest(): void
    {
        $middleware = new RequirePermission;

        $this->expectException(AuthenticationException::class);
        $middleware->handle($this->requestAs(null), $this->passThrough(), self::PERMISSION);
    }

    /**
     * Identities without `SupportsPermissions` are denied —
     * anonymous user objects cannot be probed for permissions.
     *
     * @return void
     */
    public function testPermissionMiddlewareRejectsIdentityWithoutPermissionSupport(): void
    {
        $middleware = new RequirePermission;

        $this->expectException(AccessDeniedHttpException::class);
        $middleware->handle(
            $this->requestAs(new \stdClass),
            $this->passThrough(),
            self::PERMISSION,
        );
    }

    /**
     * A user missing every required permission is denied.
     *
     * @return void
     */
    public function testPermissionMiddlewareDeniesWhenPermissionMissing(): void
    {
        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => self::PERMISSION,
            'guard_name' => 'web',
        ]);

        $user = StubAuthorizable::create(['id' => (string) Str::uuid()]);

        $middleware = new RequirePermission;

        $this->expectException(AccessDeniedHttpException::class);
        $middleware->handle($this->requestAs($user), $this->passThrough(), self::PERMISSION);
    }

    /**
     * A user with the required permission (direct grant) is admitted.
     *
     * @return void
     */
    public function testPermissionMiddlewareAdmitsDirectGrant(): void
    {
        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => self::PERMISSION,
            'guard_name' => 'web',
        ]);

        $user = StubAuthorizable::create(['id' => (string) Str::uuid()]);
        $user->givePermission(self::PERMISSION);

        $response = (new RequirePermission)->handle(
            $this->requestAs($user),
            $this->passThrough(),
            self::PERMISSION,
        );

        self::assertInstanceOf(Response::class, $response);
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * A user whose role carries the required permission is admitted —
     * `hasPermission()` folds direct + role-inherited grants.
     *
     * @return void
     */
    public function testPermissionMiddlewareAdmitsRoleInheritedGrant(): void
    {
        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'posts:publish',
            'guard_name' => 'web',
        ]);
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'publisher',
            'guard_name' => 'web',
        ]);
        $role->permissions()->attach($permission->getKey());

        $user = StubAuthorizable::create(['id' => (string) Str::uuid()]);
        $user->assignRole('publisher');

        $response = (new RequirePermission)->handle(
            $this->requestAs($user),
            $this->passThrough(),
            'posts:publish',
        );

        self::assertInstanceOf(Response::class, $response);
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * Pipe-separated permission arguments resolve to OR semantics —
     * holding either permission suffices.
     *
     * @return void
     */
    public function testPermissionMiddlewareHonoursPipeSeparatedOrSemantics(): void
    {
        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => self::PERMISSION,
            'guard_name' => 'web',
        ]);
        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'posts:delete',
            'guard_name' => 'web',
        ]);

        $user = StubAuthorizable::create(['id' => (string) Str::uuid()]);
        $user->givePermission('posts:delete');

        $response = (new RequirePermission)->handle(
            $this->requestAs($user),
            $this->passThrough(),
            'posts:edit|posts:delete',
        );

        self::assertInstanceOf(Response::class, $response);
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * The service provider registers the `role` and `permission`
     * aliases against the router's middleware map.
     *
     * @return void
     */
    public function testServiceProviderRegistersMiddlewareAliases(): void
    {
        /** @var \Illuminate\Routing\Router $router */
        $router = $this->app->make(Router::class);

        $middleware = $router->getMiddleware();

        self::assertSame(RequireRole::class, $middleware['role'] ?? null);
        self::assertSame(RequirePermission::class, $middleware['permission'] ?? null);
    }

    /**
     * Pre-existing alias bindings are preserved — the provider
     * never clobbers a consumer's own `role` / `permission`
     * middleware.
     *
     * @return void
     */
    public function testServiceProviderDoesNotOverrideExistingAliases(): void
    {
        /** @var \Illuminate\Routing\Router $router */
        $router = $this->app->make(Router::class);

        $router->aliasMiddleware('role', CustomRoleMiddlewareDouble::class);

        (new AuthorizationServiceProvider($this->app))->boot();

        $middleware = $router->getMiddleware();

        self::assertSame(CustomRoleMiddlewareDouble::class, $middleware['role'] ?? null);
    }

    /**
     * Build an incoming request carrying the supplied user as the
     * authenticated identity.
     *
     * @param  object|null  $user
     * @return \Illuminate\Http\Request
     */
    private function requestAs(?object $user): Request
    {
        $request = Request::create('/test', 'GET');
        $request->setUserResolver(static fn (): ?object => $user);

        return $request;
    }

    /**
     * A pass-through `$next` closure that proves the middleware
     * forwarded the request.
     *
     * @return \Closure(\Illuminate\Http\Request): \Illuminate\Http\Response
     */
    private function passThrough(): \Closure
    {
        return static fn (): Response => new Response('ok', 200);
    }
}
