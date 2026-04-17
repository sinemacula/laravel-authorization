<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchmarkCase;
use Benchmarks\Support\BenchTenantResolver;
use Illuminate\Support\Str;
use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Authorization\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;

/**
 * PHPBench micro-benchmark for `TenantScope::apply()`.
 *
 * The global scope fires on every Eloquent query against
 * `Role` / `Permission`. The scope memoises its resolver output
 * keyed by container `spl_object_id`, so a warm request never
 * pays the resolver cost twice. The bench carves the call
 * surface into two production shapes:
 *
 * - **Warm apply** — memoised tenant; shortcut read.
 * - **Cold apply** — memo flushed each rev; resolver runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[Bench\OutputTimeUnit('microseconds')]
final class TenantScopeBench extends BenchmarkCase
{
    /** @var \SineMacula\Laravel\Authorization\Scopes\TenantScope Scope instance shared across subjects. */
    private TenantScope $scope;

    /** @var \SineMacula\Laravel\Authorization\Models\Role Role fixture whose builder drives the scope apply. */
    private Role $role;

    /**
     * Bench setUp — boot a Laravel application, bind a tenant
     * resolver that returns a stable `AuthorizableTenant`
     * implementation, and seed a role row so the builder the
     * scope applies against has something to query.
     *
     * @return void
     */
    public function setUp(): void
    {
        $app = $this->boot();

        $app->bind(TenantResolver::class, static fn (): TenantResolver => new BenchTenantResolver);

        Role::query()->delete();

        $this->role = Role::create([
            'id'          => (string) Str::uuid(),
            'name'        => 'tenant-scope-bench',
            'guard_name'  => 'web',
            'tenant_type' => 'bench_tenant',
            'tenant_id'   => 'bench-tenant',
        ]);

        $this->scope = new TenantScope;

        // Prime the memo so the warm-apply subject observes the
        // memoised fast path from its very first revolution.
        $this->scope->apply(Role::query(), $this->role);
    }

    /**
     * Benchmark: warm apply — memo hit, no resolver call.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(5000)]
    public function benchWarmApply(): void
    {
        $this->scope->apply(Role::query(), $this->role);
    }

    /**
     * Benchmark: cold apply — memo flushed each rev so the
     * resolver runs every time. Measures the worst-case per-query
     * cost under a hot reload or mid-request tenant pivot.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchColdApply(): void
    {
        $this->scope->flushResolvedTenant();
        $this->scope->apply(Role::query(), $this->role);
    }
}
