<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchIdentity;
use Benchmarks\Support\BenchmarkCase;
use Benchmarks\Support\BenchmarkFixtures;
use Benchmarks\Support\BenchPrincipalResolver;
use Illuminate\Support\Str;
use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\BladeHelpers;

/**
 * PHPBench micro-benchmark for the Blade runtime helpers.
 *
 * Blade directives compile into static calls on `BladeHelpers`
 * that resolve the current principal through the package
 * `PrincipalResolver` on every render. A single page renders one
 * directive per permission-gated block, so the per-directive
 * cost scales with page complexity.
 *
 * The bench exercises four shapes:
 *
 * - `hasRole()` — positive match;
 * - `hasPermission()` — positive match;
 * - `hasAllRoles()` — conjunction path;
 * - `hasAllPermissions()` — conjunction path.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[Bench\OutputTimeUnit('microseconds')]
final class BladeHelpersBench extends BenchmarkCase
{
    /** @var string Benchmarked role name. */
    private string $roleName = '';

    /** Benchmarked permission names. */
    /** @var array<int, string> */
    private array $permissionNames = [];

    /**
     * Bench setUp — boot the application, seed a role that
     * carries the fixture permissions, attach it to the
     * principal, and bind a principal resolver slot.
     *
     * @return void
     */
    public function setUp(): void
    {
        $app = $this->boot();

        Role::query()->delete();
        Permission::query()->delete();
        BenchIdentity::query()->delete();

        $this->roleName        = BenchmarkFixtures::roleName();
        $this->permissionNames = BenchmarkFixtures::permissionNames();

        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => $this->roleName,
            'guard_name' => 'web',
        ]);

        foreach ($this->permissionNames as $name) {
            $permission = Permission::create([
                'id'         => (string) Str::uuid(),
                'name'       => $name,
                'guard_name' => 'web',
            ]);
            $role->permissions()->attach($permission->getKey());
        }

        $user = BenchIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole($this->roleName);

        $app->instance(PrincipalResolver::class, new BenchPrincipalResolver($user));
        $app->forgetInstance(AuthorizationManager::class);
        $app->forgetInstance('authorization');
    }

    /**
     * Benchmark: `BladeHelpers::hasRole()` — positive match.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchHasRole(): void
    {
        BladeHelpers::hasRole($this->roleName);
    }

    /**
     * Benchmark: `BladeHelpers::hasPermission()` — positive match
     * via role-inherited permission.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(500)]
    public function benchHasPermission(): void
    {
        BladeHelpers::hasPermission($this->permissionNames[0]);
    }

    /**
     * Benchmark: `BladeHelpers::hasAllRoles()` — conjunction path
     * with a single role (exits on first miss / match).
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchHasAllRoles(): void
    {
        BladeHelpers::hasAllRoles([$this->roleName]);
    }

    /**
     * Benchmark: `BladeHelpers::hasAllPermissions()` — conjunction
     * path across every seeded permission.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(200)]
    public function benchHasAllPermissions(): void
    {
        BladeHelpers::hasAllPermissions($this->permissionNames);
    }
}
