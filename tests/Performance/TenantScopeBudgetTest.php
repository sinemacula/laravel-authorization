<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use Tests\TestCase;

/**
 * Performance budget for `TenantScope::apply()`.
 *
 * The scope fires on every Eloquent query against `Role` and
 * `Permission`. The memoisation tier ensures that after the first
 * resolver call, repeated applies on the same container pay only
 * the constant-time memo lookup — the bench measures the raw cost,
 * this test asserts the shape of the amortised lookup.
 *
 * The test proves the memoisation contract: the resolver is
 * invoked exactly once across N warm applies in the same
 * container. A regression that stops respecting the memo (an
 * accidental flush per apply, a container rebuild on every
 * query) manifests as an N-call resolver count — caught here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantScope::class)]
final class TenantScopeBudgetTest extends TestCase
{
    /**
     * The memoisation tier must cap the resolver to a single call
     * across repeated apply invocations within the same
     * container — the core "constant-time after first resolve"
     * contract from the scope's docblock.
     *
     * @return void
     */
    public function testMemoisationCapsResolverCallsAcrossRepeatedApplies(): void
    {
        $app = $this->app;
        self::assertNotNull($app, 'Testbench application must be booted by setUp().');

        $resolver = new CountingTenantResolver(new CountedBenchTenant);
        $app->instance(TenantResolver::class, $resolver);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);
        $config->set('authorization.cache.store', null);

        $role = Role::create([
            'id'          => (string) Str::uuid(),
            'name'        => 'memo-budget',
            'guard_name'  => 'web',
            'tenant_type' => 'bench_tenant',
            'tenant_id'   => 'bench-tenant',
        ]);

        $scope = new TenantScope;

        for ($i = 0; $i < 50; $i++) {
            $scope->apply(Role::query(), $role);
        }

        self::assertSame(
            1,
            $resolver->calls,
            "Tenant resolver invoked {$resolver->calls} times across 50 applies — memoisation contract violated.",
        );
    }

    /**
     * 1,000 warm applies must complete under 250ms on the
     * reference machine. The bench reports ~85μs per call (~85ms
     * total); the budget gives ~3× headroom so normal CI variance
     * never trips it.
     *
     * @return void
     */
    public function testWarmApplyOverheadStaysBounded(): void
    {
        $app = $this->app;
        self::assertNotNull($app, 'Testbench application must be booted by setUp().');

        $app->instance(TenantResolver::class, new CountingTenantResolver(new CountedBenchTenant));

        $role = Role::create([
            'id'          => (string) Str::uuid(),
            'name'        => 'warm-apply-budget',
            'guard_name'  => 'web',
            'tenant_type' => 'bench_tenant',
            'tenant_id'   => 'bench-tenant',
        ]);

        $scope = new TenantScope;

        // Prime the memo so every measured call is a warm apply.
        $scope->apply(Role::query(), $role);

        $start = \microtime(true);

        for ($i = 0; $i < 1000; $i++) {
            $scope->apply(Role::query(), $role);
        }

        $elapsed = \microtime(true) - $start;

        self::assertLessThan(
            0.25,
            $elapsed,
            "TenantScope warm-apply budget exceeded ({$elapsed}s for 1,000 iterations).",
        );
    }
}

/**
 * Counting tenant resolver used by the memo-contract assertion —
 * exposes `$calls` so the test can prove single-invocation
 * semantics.
 *
 * @internal
 */
// phpcs:ignore PSR1.Classes.ClassDeclaration.MultipleClasses
final class CountingTenantResolver implements TenantResolver
{
    /** @var int */
    public int $calls = 0;

    /**
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant  $tenant
     */
    public function __construct(private readonly AuthorizableTenant $tenant) {}

    /**
     * @return object|null
     */
    public function resolve(): ?object // @phpstan-ignore return.unusedType
    {
        $this->calls++;

        return $this->tenant;
    }
}

/**
 * Minimal tenant fixture — kept here rather than in a shared
 * helper so the performance suite has no runtime dependency on
 * the benchmark-support tree.
 *
 * @internal
 */
// phpcs:ignore PSR1.Classes.ClassDeclaration.MultipleClasses
final class CountedBenchTenant implements AuthorizableTenant
{
    /**
     * @return string
     */
    public function getKey(): string
    {
        return 'bench-tenant';
    }

    /**
     * @return string
     */
    public function getMorphClass(): string
    {
        return 'bench_tenant';
    }
}
