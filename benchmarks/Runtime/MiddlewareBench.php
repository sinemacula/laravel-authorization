<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchIdentity;
use Benchmarks\Support\BenchmarkCase;
use Benchmarks\Support\BenchmarkFixtures;
use Benchmarks\Support\BenchPrincipalResolver;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Str;
use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Http\Middleware\RequirePermission;
use SineMacula\Laravel\Authorization\Http\Middleware\RequireRole;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * PHPBench micro-benchmark for `RequireRole::handle()` and
 * `RequirePermission::handle()`.
 *
 * Every route decorated with `role:` or `permission:` routes a
 * request through one of these middleware before the controller
 * runs. The bench measures the admit path (the optimistic case
 * that never throws) for both middlewares — this covers principal
 * resolution through the facade, contract checks, needle expansion,
 * and the per-needle `matches()` dispatch. A reject path is
 * deliberately not benched: throwing is the uncommon case and
 * exception construction dominates any regression signal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[Bench\OutputTimeUnit('microseconds')]
final class MiddlewareBench extends BenchmarkCase
{
    /** Role middleware instance under test. */
    /** @phpstan-ignore-next-line property.uninitialized, missingType.callable */
    private RequireRole $roleMiddleware;

    /** Permission middleware instance under test. */
    /** @phpstan-ignore-next-line property.uninitialized, missingType.callable */
    private RequirePermission $permissionMiddleware;

    /** Pass-through next closure — every admit path calls it exactly once. */
    /** @phpstan-ignore-next-line property.uninitialized, missingType.callable */
    private \Closure $next;

    /** Incoming request stand-in — shared across every rev. */
    /** @phpstan-ignore-next-line property.uninitialized, missingType.callable */
    private Request $request;

    /**
     * Bench setUp — boot the Laravel application, seed a role
     * that carries the fixture permissions, and bind a principal
     * resolver that returns the seeded identity.
     *
     * @return void
     */
    public function setUp(): void
    {
        $app = $this->boot();

        Role::query()->delete();
        Permission::query()->delete();
        BenchIdentity::query()->delete();

        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => BenchmarkFixtures::roleName(),
            'guard_name' => 'web',
        ]);

        foreach (BenchmarkFixtures::permissionNames() as $name) {
            $permission = Permission::create([
                'id'         => (string) Str::uuid(),
                'name'       => $name,
                'guard_name' => 'web',
            ]);
            $role->permissions()->attach($permission->getKey());
        }

        $user = BenchIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole(BenchmarkFixtures::roleName());

        $app->instance(PrincipalResolver::class, new BenchPrincipalResolver($user));

        $app->forgetInstance(AuthorizationManager::class);
        $app->forgetInstance('authorization');

        $this->roleMiddleware       = new RequireRole;
        $this->permissionMiddleware = new RequirePermission;
        $this->next                 = static fn (): Response => new Response('ok', 200);
        $this->request              = Request::create('/bench', 'GET');
    }

    /**
     * Benchmark: `RequireRole::handle()` — admit path, single
     * needle match.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchRequireRoleAdmit(): void
    {
        $this->roleMiddleware->handle($this->request, $this->next, BenchmarkFixtures::roleName());
    }

    /**
     * Benchmark: `RequirePermission::handle()` — admit path,
     * single needle match via role-inherited permission.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(500)]
    public function benchRequirePermissionAdmit(): void
    {
        $this->permissionMiddleware->handle($this->request, $this->next, BenchmarkFixtures::permissionNames()[0]);
    }
}
