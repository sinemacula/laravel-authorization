<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchmarkCase;
use Benchmarks\Support\BenchmarkSubjectResolver;
use Benchmarks\Support\BenchmarkTenant;
use Illuminate\Support\Str;
use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;

/**
 * PHPBench micro-benchmark for `TenantScope::apply()`.
 *
 * The global scope fires on every Eloquent query against `Role` / `Permission`.
 * The tenant is resolved once per request or job and held in the container, so
 * a warm request never pays the resolver cost twice. Each iteration binds one
 * resolver instance, as a request has one, and the bench carves the call
 * surface into two production shapes:
 *
 * - Warm apply — tenant resolved once in setUp; each rev reads the held tenant.
 * - Cold apply — held tenant forgotten each rev; the resolver runs every time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[Bench\OutputTimeUnit('microseconds')]
final class TenantScopeBench extends BenchmarkCase
{
    /** @var \SineMacula\Laravel\Authorization\Scopes\TenantScope Scope instance shared across subjects. */
    private TenantScope $scope; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Authorization\Models\Role Role fixture whose builder drives the scope apply. */
    private Role $role; // @phpstan-ignore property.uninitialized

    /**
     * Bench setUp — boot a Laravel application, bind one subject resolver
     * instance whose subject carries a stable `AuthorizableTenant`, and seed a
     * role row so the builder the scope applies against has something to query.
     *
     * @return void
     */
    public function setUp(): void
    {
        $app = $this->boot();

        $app->instance(SubjectResolver::class, new BenchmarkSubjectResolver(new \stdClass, new BenchmarkTenant));

        Role::query()->delete();

        $this->role = Role::create([
            'id'          => (string) Str::uuid(),
            'name'        => 'tenant-scope-bench',
            'guard'       => 'web',
            'tenant_type' => 'bench_tenant',
            'tenant_id'   => 'bench-tenant',
        ]);

        $this->scope = new TenantScope;

        // Resolve the tenant once, as the first query of a request does, so the
        // warm-apply subject reads the held tenant from its very first
        // revolution.
        $this->scope->apply(Role::query(), $this->role);
    }

    /**
     * Benchmark: warm apply — the held tenant is read, no resolver call.
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
     * Benchmark: cold apply — the held tenant is forgotten each rev so the
     * resolver runs every time. Measures the worst-case per-query cost under a
     * hot reload or mid-request tenant pivot.
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
