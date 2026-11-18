<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Route;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Http\Middleware\AbstractAuthorizationMiddleware;
use SineMacula\Laravel\Authorization\Http\Middleware\AuthorizeAction;
use SineMacula\Laravel\Authorization\Http\Middleware\RequirePermission;
use SineMacula\Laravel\Authorization\Http\Middleware\RequireRole;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Concerns\MeasuresTime;
use Tests\Feature\Stubs\StubGrantee;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\QueryScoping\TenantScopedPost;
use Tests\TestCase;

/**
 * Performance budget for the `role:`, `permission:` and `authorize:`
 * middleware.
 *
 * The middleware runs on every request decorated with `role:` or `permission:`.
 * The budget bounds the admit-path cost on 500 iterations — enough to amortise
 * microsecond-level jitter while staying well under a second so the suite stays
 * fast. Observed ~25μs per admit for RequireRole and ~72μs for
 * RequirePermission on the reference machine. `authorize:` on a bound model has
 * a query budget per request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AbstractAuthorizationMiddleware::class)]
#[CoversClass(RequireRole::class)]
#[CoversClass(RequirePermission::class)]
#[CoversClass(AuthorizeAction::class)]
final class MiddlewareBudgetTest extends TestCase
{
    use MeasuresTime;

    /**
     * 500 admit-path invocations of `RequireRole::handle()` must complete in
     * under 250ms on the reference machine (~25μs per call observed; ~10×
     * budget for CI variance).
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
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

        $this->assertWithinBudget(
            0.25,
            $elapsed,
            "RequireRole admit-path budget exceeded ({$elapsed}s for 500 iterations).",
        );
    }

    /**
     * 500 admit-path invocations of `RequirePermission::handle()` must complete
     * in under 500ms on the reference machine (~72μs per call observed; the
     * role-inherited resolve is the heavier path).
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testRequirePermissionAdmitOverheadStaysBounded(): void
    {
        $role = $this->seedRole();

        $permission = Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'posts:edit',
            'guard' => 'web',
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

        $this->assertWithinBudget(
            0.5,
            $elapsed,
            "RequirePermission admit-path budget exceeded ({$elapsed}s for 500 iterations).",
        );
    }

    /**
     * Admitting a bound model of the subject's tenant through `AuthorizeAction`
     * reads at most six queries: the grants a resource-less admit reads and the
     * policies attached to the model. Resolving the model's tenant from its
     * columns reads nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testAuthorizeActionAdmitOnABoundModelStaysWithinItsQueryBudget(): void
    {
        config(['authorization.events.decisions.allows' => 'all']);
        Event::fake([DecisionEvaluated::class]);

        $tenant = StubTenant::create(['id' => 'tenant-a']);
        $user   = StubGrantee::create(['id' => (string) Str::uuid()]);
        $post   = TenantScopedPost::query()->create(['id' => 1, 'tenant_type' => $tenant->getMorphClass(), 'tenant_id' => 'tenant-a']);

        $user->givePermission(Permission::create(['name' => 'posts:edit']), null, $tenant);
        $this->actAs($user, $tenant);

        $request = Request::create('/posts/1', 'GET');
        $route   = (new Route(['GET'], '/posts/{post}', static fn (): string => 'ok'))->bind($request);

        $route->setParameter('post', $post);
        $request->setRouteResolver(static fn (): Route => $route);

        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        $response = (new AuthorizeAction)->handle($request, static fn (): Response => new Response('ok', 200), 'posts:edit', 'post');

        self::assertInstanceOf(Response::class, $response);
        self::assertSame('ok', $response->getContent());
        self::assertLessThanOrEqual(6, $queries, 'AuthorizeAction exceeded its six-query budget for one request.');
        Event::assertDispatched(DecisionEvaluated::class, static fn (DecisionEvaluated $event): bool => $event->resource === $post->getMorphClass() . ':1');
    }

    /**
     * Seed the role the admit-path subjects rely on.
     *
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private function seedRole(): Role
    {
        return Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'admin',
            'guard' => 'web',
        ]);
    }

    /**
     * Seed the user that will pass the admit check.
     *
     * @return \Tests\Feature\Stubs\StubGrantee
     */
    private function seedAdmitUser(): StubGrantee
    {
        $user = StubGrantee::create(['id' => (string) Str::uuid()]);
        $user->assignRole('admin');

        return $user;
    }

    /**
     * Bind a subject resolver that returns the supplied subject, so the budget
     * exercises the middleware through the package's own resolver contract, as
     * the feature middleware tests do.
     *
     * @param  object  $principal
     * @param  object|null  $tenant
     * @return void
     */
    private function actAs(object $principal, ?object $tenant = null): void
    {
        $resolver = new StubSubjectResolver($principal, $tenant);

        $app = $this->app;
        self::assertNotNull($app, 'Testbench application must be booted by setUp().');

        $app->instance(SubjectResolver::class, $resolver);
        $app->forgetInstance('authorization');
        $app->forgetInstance(AuthorizationManager::class);
    }
}
