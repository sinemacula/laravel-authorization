<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Http\Middleware\AbstractAuthorizationMiddleware;
use SineMacula\Laravel\Authorization\Http\Middleware\RequirePermission;
use SineMacula\Laravel\Authorization\Http\Middleware\RequireRole;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Performance budget for `RequireRole` / `RequirePermission`
 * middleware.
 *
 * The middleware runs on every request decorated with `role:` or
 * `permission:`. The budget bounds the admit-path cost on 500
 * iterations — enough to amortise microsecond-level jitter while
 * staying well under a second so the suite stays fast. Observed
 * ~25μs per admit for RequireRole and ~72μs for RequirePermission
 * on the reference machine.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractAuthorizationMiddleware::class)]
#[CoversClass(RequireRole::class)]
#[CoversClass(RequirePermission::class)]
final class MiddlewareBudgetTest extends TestCase
{
    /**
     * 500 admit-path invocations of `RequireRole::handle()` must
     * complete in under 250ms on the reference machine (~25μs
     * per call observed; ~10× budget for CI variance).
     *
     * @return void
     */
    public function testRequireRoleAdmitOverheadStaysBounded(): void
    {
        $this->seedRole();
        $user = $this->seedAdmitUser();
        $this->actAs($user);

        $middleware = new RequireRole;
        $request    = Request::create('/budget', 'GET');
        $next       = static fn (): Response => new Response('ok', 200);

        $start = \microtime(true);

        for ($i = 0; $i < 500; $i++) {
            $middleware->handle($request, $next, 'admin');
        }

        $elapsed = \microtime(true) - $start;

        self::assertLessThan(
            0.25,
            $elapsed,
            "RequireRole admit-path budget exceeded ({$elapsed}s for 500 iterations).",
        );
    }

    /**
     * 500 admit-path invocations of `RequirePermission::handle()`
     * must complete in under 500ms on the reference machine
     * (~72μs per call observed; the role-inherited resolve is the
     * heavier path).
     *
     * @return void
     */
    public function testRequirePermissionAdmitOverheadStaysBounded(): void
    {
        $role = $this->seedRole();

        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'posts:edit',
            'guard_name' => 'web',
        ]);
        $role->permissions()->attach($permission->getKey());

        $user = $this->seedAdmitUser();
        $this->actAs($user);

        $middleware = new RequirePermission;
        $request    = Request::create('/budget', 'GET');
        $next       = static fn (): Response => new Response('ok', 200);

        $start = \microtime(true);

        for ($i = 0; $i < 500; $i++) {
            $middleware->handle($request, $next, 'posts:edit');
        }

        $elapsed = \microtime(true) - $start;

        self::assertLessThan(
            0.5,
            $elapsed,
            "RequirePermission admit-path budget exceeded ({$elapsed}s for 500 iterations).",
        );
    }

    /**
     * Seed the role the admit-path subjects rely on.
     *
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private function seedRole(): Role
    {
        return Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'admin',
            'guard_name' => 'web',
        ]);
    }

    /**
     * Seed the user that will pass the admit check.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function seedAdmitUser(): StubIdentity
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole('admin');

        return $user;
    }

    /**
     * Bind a principal resolver that returns the supplied
     * principal — mirrors the helper used by the feature
     * `RouteMiddlewareTest` so both suites exercise the
     * middleware through the package's own resolver contract.
     *
     * @param  object  $principal
     * @return void
     */
    private function actAs(object $principal): void
    {
        $resolver = new class ($principal) implements PrincipalResolver {
            /**
             * @param  object  $principal
             */
            public function __construct(private readonly object $principal) {}

            /**
             * @return object|null
             */
            public function resolve(): ?object
            {
                return $this->principal;
            }
        };

        $app = $this->app;
        self::assertNotNull($app, 'Testbench application must be booted by setUp().');

        $app->instance(PrincipalResolver::class, $resolver);
        $app->forgetInstance('authorization');
        $app->forgetInstance(AuthorizationManager::class);
    }
}
