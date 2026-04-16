<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchmarkCase;
use Benchmarks\Support\BenchmarkFixtures;
use Illuminate\Support\Str;
use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * PHPBench micro-benchmark for `Role::resolveByName()`.
 *
 * Exercises the two precedence branches the guard-scoped lookup
 * supports: a guard-specific row (`guard_name = 'web'`) and a
 * guard-agnostic row (`guard_name = null`). Together they cover the
 * disjunction the hot path has to evaluate on every RBAC check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[Bench\OutputTimeUnit('microseconds')]
final class RoleLookupBench extends BenchmarkCase
{
    /**
     * Bench setUp — boot a Laravel application and seed the two
     * role rows that the lookup branches target.
     *
     * @return void
     */
    public function setUp(): void
    {
        $this->boot();

        Role::query()->delete();

        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => BenchmarkFixtures::roleName(),
            'guard_name' => 'web',
        ]);

        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => BenchmarkFixtures::roleName() . '-agnostic',
            'guard_name' => null,
        ]);
    }

    /**
     * Benchmark: guard-specific lookup (guard row beats agnostic row).
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(100)]
    public function benchResolveByNameGuardSpecific(): void
    {
        Role::resolveByName(BenchmarkFixtures::roleName(), 'web');
    }

    /**
     * Benchmark: guard-agnostic lookup (no guard-specific row exists).
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(100)]
    public function benchResolveByNameGuardAgnostic(): void
    {
        Role::resolveByName(BenchmarkFixtures::roleName() . '-agnostic', 'web');
    }
}
