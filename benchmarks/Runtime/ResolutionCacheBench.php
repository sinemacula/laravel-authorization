<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchmarkCase;
use Benchmarks\Support\BenchmarkFixtures;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository as CacheRepository;
use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * PHPBench micro-benchmark for `ResolutionCache`.
 *
 * The cache sits on every `can()` and `hasPermission()` evaluation in the
 * request. Four subjects cover the shapes that production traffic actually
 * hits:
 *
 * - `rememberRoles()` memo-tier hit after prime;
 * - `rememberPermissions()` memo-tier hit after prime;
 * - `rememberPolicies()` persistent-tier hit (memo miss, then the entry and its
 *   versions read from the store);
 * - invalidating a grantee, as every write does: its version keys worked out
 *   from the event, then bumped.
 *
 * The array store stands in for a production store. The application is booted
 * because entry keys carry the tenant the tenant scope applies.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ResolutionCacheBench extends BenchmarkCase
{
    /** @var \SineMacula\Laravel\Authorization\Cache\ResolutionCache A cache with the memo only, primed. */
    private ResolutionCache $memoOnly; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Authorization\Cache\ResolutionCache A cache over the array store, primed. */
    private ResolutionCache $persisted; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Authorization\Support\Reference The grantee every subject resolves for. */
    private Reference $principal; // @phpstan-ignore property.uninitialized

    /** @var \Closure(): \SineMacula\Laravel\Authorization\Cache\Resolution<string> The roles resolution. */
    private \Closure $roleResolver; // @phpstan-ignore property.uninitialized

    /** @var \Closure(): \SineMacula\Laravel\Authorization\Cache\Resolution<string> The permissions resolution. */
    private \Closure $permissionResolver; // @phpstan-ignore property.uninitialized

    /** @var \Closure(): \SineMacula\Laravel\Authorization\Cache\Resolution<\SineMacula\Laravel\Authorization\Evaluation\Policy> The policies resolution. */
    private \Closure $policyResolver; // @phpstan-ignore property.uninitialized

    /** @var list<\SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent> The events of one grant. */
    private array $events; // @phpstan-ignore property.uninitialized

    /**
     * Bench setUp — boot the application, prime a memo-only cache, and prime a
     * persistent cache whose memo is then dropped so every revolution reads the
     * store.
     *
     * @return void
     */
    public function setUp(): void
    {
        $this->boot();

        $this->principal = new Reference('bench_identity', 'bench-principal');

        $permissions = BenchmarkFixtures::permissionNames();
        $roles       = [BenchmarkFixtures::roleName()];
        $policies    = [BenchmarkFixtures::policy()];

        $this->roleResolver       = static fn (): Resolution => new Resolution($roles);
        $this->permissionResolver = static fn (): Resolution => new Resolution($permissions);
        $this->policyResolver     = static fn (): Resolution => new Resolution($policies);

        $this->memoOnly = new ResolutionCache(store: null, prefix: 'bench-memo');
        $this->memoOnly->rememberRoles($this->principal, $this->roleResolver);
        $this->memoOnly->rememberPermissions($this->principal, $this->permissionResolver);

        $this->persisted = new ResolutionCache(store: new CacheRepository(new ArrayStore), prefix: 'bench-persisted');
        $this->persisted->rememberPolicies($this->principal, $this->policyResolver);

        $this->events = [new RoleAssigned(Operation::begin(), $this->principal, new Reference('role', 'role-1'), 'editor', GrantScope::platform(), null)];
    }

    /**
     * A memo hit for the roles.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(10000)]
    public function benchRememberRolesMemoHit(): void
    {
        $this->memoOnly->rememberRoles($this->principal, $this->roleResolver);
    }

    /**
     * A memo hit for the permissions.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(10000)]
    public function benchRememberPermissionsMemoHit(): void
    {
        $this->memoOnly->rememberPermissions($this->principal, $this->permissionResolver);
    }

    /**
     * A store hit for the policies: the entry and its versions read, and the
     * documents hydrated.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(2000)]
    public function benchRememberPoliciesPersistentHit(): void
    {
        // Empty the memo each rev so the read drops to the store; otherwise the
        // memo masks the persistent-tier cost.
        $this->persisted->invalidate([]);
        $this->persisted->rememberPolicies($this->principal, $this->policyResolver);
    }

    /**
     * Invalidating a grantee, as every write does: its version keys worked out
     * from the event, then bumped.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(2000)]
    public function benchInvalidateAGrantee(): void
    {
        $this->persisted->invalidate($this->persisted->versionKeys($this->events));
    }
}
