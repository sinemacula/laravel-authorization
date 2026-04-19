<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchmarkCase;
use Benchmarks\Support\BenchmarkFixtures;
use Benchmarks\Support\BenchmarkIdentity;
use Illuminate\Support\Str;
use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy as PolicyModel;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * PHPBench micro-benchmark for the full `AuthorizationManager` pipeline.
 *
 * Exercises the four decision paths that matter in production:
 *
 * - RBAC allow via role-inherited permission;
 * - explicit policy allow;
 * - explicit policy deny overriding an RBAC allow;
 * - implicit deny (no matching statement, no RBAC grant).
 *
 * Each subject drives the pipeline through principal resolution (the explicit
 * `for($user)` override), policy gathering, statement evaluation, and RBAC
 * fallback — the same chain the facade invokes on every request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[Bench\OutputTimeUnit('microseconds')]
final class AuthorizationManagerBench extends BenchmarkCase
{
    /** @var \SineMacula\Laravel\Authorization\AuthorizationManager|null Container-resolved manager under test; populated by `setUp()`. */
    private ?AuthorizationManager $manager = null;

    /** @var \Benchmarks\Support\BenchmarkIdentity|null Seeded principal with a role + policy; populated by `setUp()`. */
    private ?BenchmarkIdentity $user = null;

    /**
     * Bench setUp — boot the application, seed a role carrying the fixture
     * permissions, attach an allow-and-deny policy, and resolve the
     * container-bound manager.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function setUp(): void
    {
        $app = $this->boot();

        $this->resetFixtureTables();

        $user = $this->seedRoleAndPrincipal();
        $this->attachBenchmarkPolicy($user);

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $manager */
        $manager = $app->make(AuthorizationManager::class);

        $this->manager = $manager;
        $this->user    = $user;
    }

    /**
     * Benchmark: RBAC allow via role-inherited permission.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(100)]
    public function benchRbacAllow(): void
    {
        $this->getManager()->for($this->getUser())->can('posts:create');
    }

    /**
     * Return the manager seeded by `setUp()`, asserting it is populated —
     * PHPBench `@BeforeMethods` guarantees the setup hook has run before the
     * subject methods.
     *
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    public function getManager(): AuthorizationManager
    {
        \assert($this->manager !== null, 'setUp() must populate $manager before a subject method runs.');

        return $this->manager;
    }

    /**
     * Return the principal seeded by `setUp()`.
     *
     * @return \Benchmarks\Support\BenchmarkIdentity
     */
    public function getUser(): BenchmarkIdentity
    {
        \assert($this->user !== null, 'setUp() must populate $user before a subject method runs.');

        return $this->user;
    }

    /**
     * Benchmark: explicit policy allow (RBAC does not grant this).
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(100)]
    public function benchPolicyAllow(): void
    {
        $this->getManager()->for($this->getUser())->can('reports:read');
    }

    /**
     * Benchmark: explicit policy deny overriding an RBAC allow.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(100)]
    public function benchPolicyDenyOverride(): void
    {
        $this->getManager()->for($this->getUser())->can('posts:delete');
    }

    /**
     * Benchmark: implicit deny (no matching statement or grant).
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(100)]
    public function benchImplicitDeny(): void
    {
        $this->getManager()->for($this->getUser())->can('unknown:action');
    }

    /**
     * Truncate the fixture tables so each iteration starts from a known-empty
     * state.
     *
     * @return void
     */
    private function resetFixtureTables(): void
    {
        Role::query()->delete();
        Permission::query()->delete();
        PolicyModel::query()->delete();
        BenchmarkIdentity::query()->delete();
    }

    /**
     * Seed a role carrying the fixture permissions, create the principal, and
     * assign the role.
     *
     * @return \Benchmarks\Support\BenchmarkIdentity
     */
    private function seedRoleAndPrincipal(): BenchmarkIdentity
    {
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

        $user = BenchmarkIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole(BenchmarkFixtures::roleName());

        return $user;
    }

    /**
     * Attach the allow-and-deny benchmark policy to the given principal.
     *
     * @param  \Benchmarks\Support\BenchmarkIdentity  $user
     * @return void
     */
    private function attachBenchmarkPolicy(BenchmarkIdentity $user): void
    {
        $user->attachPolicy(PolicyModel::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'bench-policy',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['reports:read']],
                    ['effect' => 'deny', 'actions' => ['posts:delete']],
                ],
            ],
        ]));
    }
}
