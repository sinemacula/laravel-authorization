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
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Http\Middleware\AbstractAuthorizationMiddleware;
use SineMacula\Laravel\Authorization\Http\Middleware\AuthorizationMiddlewareMisconfiguredException;
use SineMacula\Laravel\Authorization\Http\Middleware\RequirePermission;
use SineMacula\Laravel\Authorization\Http\Middleware\RequireRole;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Tests\Feature\Stubs\CustomRoleMiddlewareDouble;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature coverage for the shipped route middleware.
 *
 * Each test binds a scoped `PrincipalResolver` that returns the chosen
 * principal, then invokes `handle()` directly — this verifies the middleware
 * resolves through the package's own resolver contract (not `$request->user()`)
 * and keeps the tests orthogonal to Laravel's auth-provider plumbing.
 * Service-provider aliasing is covered separately via the router binding.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RequireRole::class)]
#[CoversClass(RequirePermission::class)]
#[CoversClass(AbstractAuthorizationMiddleware::class)]
#[CoversClass(AuthorizationMiddlewareMisconfiguredException::class)]
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(GateRegistrar::class)]
#[CoversClass(BladeDirectiveRegistrar::class)]
#[CoversClass(EventListenerRegistrar::class)]
final class RouteMiddlewareTest extends TestCase
{
    /** @var string Permission string reused across the `permission` middleware coverage. */
    private const string PERMISSION = 'posts:edit';

    /**
     * Unauthenticated requests raise `AuthenticationException` — Laravel's
     * exception handler renders that as a 401.
     *
     * @return void
     */
    public function testRoleMiddlewareRejectsUnauthenticatedRequest(): void
    {
        $this->actAs(null);

        $middleware = new RequireRole;

        $this->expectException(AuthenticationException::class);
        $middleware->handle(self::request(), $this->passThrough(), 'admin');
    }

    /**
     * An authenticated identity that does not implement `SupportsRoles` is a
     * misconfiguration — the middleware must raise the typed misconfiguration
     * exception (HTTP 500 semantics), not an `AccessDeniedHttpException` that
     * looks like a legitimate deny.
     *
     * @return void
     */
    public function testRoleMiddlewareRaisesMisconfigurationWhenIdentityLacksContract(): void
    {
        $this->actAs(new \stdClass);

        $middleware = new RequireRole;

        $this->expectException(AuthorizationMiddlewareMisconfiguredException::class);
        $middleware->handle(self::request(), $this->passThrough(), 'admin');
    }

    /**
     * A user missing every required role is denied with a 403.
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

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $middleware = new RequireRole;

        $this->expectException(AccessDeniedHttpException::class);
        $middleware->handle(self::request(), $this->passThrough(), 'admin');
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

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole('admin');

        $this->actAs($user);

        $response = (new RequireRole)->handle(
            self::request(),
            $this->passThrough(),
            'admin',
        );

        self::assertInstanceOf(Response::class, $response);
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * Comma-separated role arguments (Laravel native) resolve to OR semantics —
     * holding either role is enough.
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

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole('editor');

        $this->actAs($user);

        $response = (new RequireRole)->handle(
            self::request(),
            $this->passThrough(),
            'admin',
            'editor',
        );

        self::assertInstanceOf(Response::class, $response);
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * Pipe-separated role arguments (Spatie convention) expand identically to
     * the comma form — holding either role suffices.
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

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole('oncall');

        $this->actAs($user);

        $response = (new RequireRole)->handle(
            self::request(),
            $this->passThrough(),
            'admin|oncall',
        );

        self::assertInstanceOf(Response::class, $response);
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * Mixed separator forms are tolerated — a pipe inside one argument and a
     * comma across arguments should both expand.
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

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole('captain');

        $this->actAs($user);

        $response = (new RequireRole)->handle(
            self::request(),
            $this->passThrough(),
            'admin|editor',
            'captain',
        );

        self::assertInstanceOf(Response::class, $response);
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * `RequirePermission` rejects unauthenticated requests the same way
     * `RequireRole` does.
     *
     * @return void
     */
    public function testPermissionMiddlewareRejectsUnauthenticatedRequest(): void
    {
        $this->actAs(null);

        $middleware = new RequirePermission;

        $this->expectException(AuthenticationException::class);
        $middleware->handle(self::request(), $this->passThrough(), self::PERMISSION);
    }

    /**
     * Identities without `SupportsPermissions` raise the typed misconfiguration
     * exception — same contract as `RequireRole`.
     *
     * @return void
     */
    public function testPermissionMiddlewareRaisesMisconfigurationWhenIdentityLacksContract(): void
    {
        $this->actAs(new \stdClass);

        $middleware = new RequirePermission;

        $this->expectException(AuthorizationMiddlewareMisconfiguredException::class);
        $middleware->handle(self::request(), $this->passThrough(), self::PERMISSION);
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

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $this->actAs($user);

        $middleware = new RequirePermission;

        $this->expectException(AccessDeniedHttpException::class);
        $middleware->handle(self::request(), $this->passThrough(), self::PERMISSION);
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

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission(self::PERMISSION);

        $this->actAs($user);

        $response = (new RequirePermission)->handle(
            self::request(),
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

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole('publisher');

        $this->actAs($user);

        $response = (new RequirePermission)->handle(
            self::request(),
            $this->passThrough(),
            'posts:publish',
        );

        self::assertInstanceOf(Response::class, $response);
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * Pipe-separated permission arguments resolve to OR semantics — holding
     * either permission suffices.
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

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission('posts:delete');

        $this->actAs($user);

        $response = (new RequirePermission)->handle(
            self::request(),
            $this->passThrough(),
            self::PERMISSION . '|posts:delete',
        );

        self::assertInstanceOf(Response::class, $response);
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * The service provider registers the `role` and `permission` aliases
     * against the router's middleware map.
     *
     * @return void
     */
    public function testServiceProviderRegistersMiddlewareAliases(): void
    {
        /** @var \Illuminate\Routing\Router $router */
        $router = $this->app->make(Router::class); // @phpstan-ignore method.nonObject

        $middleware = $router->getMiddleware();

        self::assertSame(RequireRole::class, $middleware['role'] ?? null);
        self::assertSame(RequirePermission::class, $middleware['permission'] ?? null);
    }

    /**
     * Pre-existing alias bindings are preserved — the provider never clobbers a
     * consumer's own `role` / `permission` middleware.
     *
     * @return void
     */
    public function testServiceProviderDoesNotOverrideExistingAliases(): void
    {
        /** @var \Illuminate\Routing\Router $router */
        $router = $this->app->make(Router::class); // @phpstan-ignore method.nonObject

        $router->aliasMiddleware('role', CustomRoleMiddlewareDouble::class);

        (new AuthorizationServiceProvider($this->app))->boot();

        $middleware = $router->getMiddleware();

        self::assertSame(CustomRoleMiddlewareDouble::class, $middleware['role'] ?? null);
    }

    /**
     * The middleware resolves the principal through the bound
     * `PrincipalResolver`. A request carrying a `$request->user()` that does
     * NOT match the resolver's answer must not leak in — the resolver is the
     * single source of truth.
     *
     * @return void
     */
    public function testMiddlewareResolvesPrincipalThroughResolverNotRequestUser(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'admin',
            'guard_name' => 'web',
        ]);

        $resolverUser = StubIdentity::create(['id' => (string) Str::uuid()]);
        $resolverUser->assignRole('admin');

        $requestUser = StubIdentity::create(['id' => (string) Str::uuid()]);

        $this->actAs($resolverUser);

        $request = Request::create('/test', 'GET');
        $request->setUserResolver(static fn (): object => $requestUser);

        $response = (new RequireRole)->handle(
            $request,
            $this->passThrough(),
            'admin',
        );

        self::assertInstanceOf(Response::class, $response);
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * Bind a scoped `PrincipalResolver` that returns the supplied principal and
     * drop the memoised manager so the next facade call picks it up.
     *
     * @param  object|null  $principal
     * @return void
     */
    private function actAs(?object $principal): void
    {
        $resolver = new class ($principal) implements PrincipalResolver {
            /**
             * Create a new resolver wrapping a fixed principal.
             *
             * @param  object|null  $principal
             * @return void
             */
            public function __construct(

                /** The principal returned by every resolution call. */
                private readonly ?object $principal,

            ) {}

            /**
             * Return the principal bound on this scoped resolver.
             *
             * @return object|null
             */
            #[\Override]
            public function resolve(): ?object
            {
                return $this->principal;
            }
        };

        $this->app->instance(PrincipalResolver::class, $resolver); // @phpstan-ignore method.nonObject
        $this->app->forgetInstance('authorization'); // @phpstan-ignore method.nonObject
        $this->app->forgetInstance(AuthorizationManager::class); // @phpstan-ignore method.nonObject
    }

    /**
     * Build an incoming request. The middleware no longer pulls the user from
     * `$request->user()`, so the request itself is just a transport — nothing
     * is attached to it.
     *
     * @return \Illuminate\Http\Request
     */
    private static function request(): Request
    {
        return Request::create('/test', 'GET');
    }

    /**
     * A pass-through `$next` closure that proves the middleware forwarded the
     * request.
     *
     * @return \Closure(\Illuminate\Http\Request): \Illuminate\Http\Response
     */
    private function passThrough(): \Closure
    {
        return static fn (): Response => new Response('ok', 200);
    }
}
