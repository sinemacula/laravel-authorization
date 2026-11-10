<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchmarkCase;
use Benchmarks\Support\BenchmarkFixtures;
use Illuminate\Support\Str;
use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\RoleService;

/**
 * PHPBench micro-benchmark for `RoleService::find()`.
 *
 * Exercises the two precedence branches the guard-scoped lookup supports: a
 * guard-specific row (`guard = 'web'`) and a guard-agnostic row (`guard =
 * null`). Together they cover the disjunction the hot path has to evaluate on
 * every RBAC check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[Bench\OutputTimeUnit('microseconds')]
final class RoleLookupBench extends BenchmarkCase
{
    /** @var \SineMacula\Laravel\Authorization\Services\RoleService|null Container-resolved role service under test; populated by `setUp()`. */
    private ?RoleService $roles = null;

    /**
     * Bench setUp — boot a Laravel application, seed the two role rows that the
     * lookup branches target, and resolve the container-bound role service.
     *
     * @return void
     */
    public function setUp(): void
    {
        $this->roles = $this->boot()->make(RoleService::class);

        Role::query()->delete();

        Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => BenchmarkFixtures::roleName(),
            'guard' => 'web',
        ]);

        Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => BenchmarkFixtures::roleName() . '-agnostic',
            'guard' => null,
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
        $this->roles?->find(BenchmarkFixtures::roleName(), 'web');
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
        $this->roles?->find(BenchmarkFixtures::roleName() . '-agnostic', 'web');
    }
}
