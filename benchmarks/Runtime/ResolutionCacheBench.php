<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchmarkFixtures;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository as CacheRepository;
use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;

/**
 * PHPBench micro-benchmark for `ResolutionCache`.
 *
 * The cache sits on every `can()` and `hasPermission()` evaluation
 * in the request. Four subjects cover the shapes that production
 * traffic actually hits:
 *
 * - `rememberRoles()` memo-tier hit after prime;
 * - `rememberPermissions()` memo-tier hit after prime;
 * - `rememberPolicies()` persistent-tier hit (memo miss → store read);
 * - `forget()` on a tag-capable store — the listener path that
 *   fires on `IdentityRoleAssigned` and friends.
 *
 * The bench constructs the cache directly (no Laravel boot) and
 * uses the array store as a stand-in for a tag-capable production
 * store; this is the same driver the resolution-cache test tier
 * exercises, so behaviour and capability flag match production.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[Bench\OutputTimeUnit('microseconds')]
final class ResolutionCacheBench
{
    /** @var \SineMacula\Laravel\Authorization\Cache\ResolutionCache Cache instance used for the memo-tier subjects (no persistent store). */
    /** @phpstan-ignore-next-line property.uninitialized, missingType.callable */
    private ResolutionCache $memoOnly;

    /** @var \SineMacula\Laravel\Authorization\Cache\ResolutionCache Cache instance used for the persistent-tier subjects (array-store-backed). */
    /** @phpstan-ignore-next-line property.uninitialized, missingType.callable */
    private ResolutionCache $persisted;

    /** @var \SineMacula\Laravel\Authorization\Cache\ResolutionCache Cache instance used for the `forget()` subject — reprimed between reps via `setUpForget()`. */
    /** @phpstan-ignore-next-line property.uninitialized, missingType.callable */
    private ResolutionCache $forgetTarget;

    /** @var object Principal stand-in — primitive object keyed by a stable hash. */
    /** @phpstan-ignore-next-line property.uninitialized, missingType.callable */
    private object $principal;

    /** @var \Closure Resolved role list primed into the cache before memo / persistent reads. */
    /** @phpstan-ignore-next-line property.uninitialized, missingType.callable */
    private \Closure $roleResolver;

    /** @var \Closure Resolved permission list primed into the cache before memo reads. */
    /** @phpstan-ignore-next-line property.uninitialized, missingType.callable */
    private \Closure $permissionResolver;

    /** @var \Closure Policy list primed into the persistent tier before policy reads. */
    /** @phpstan-ignore-next-line property.uninitialized, missingType.callable */
    private \Closure $policyResolver;

    /**
     * Bench setUp — prime every subject's fixtures so revolutions
     * measure the target path (memo hit, store read, forget).
     *
     * @return void
     */
    public function setUp(): void
    {
        $this->principal = new class {
            /** @var string */
            public string $id = 'bench-principal';

            public function getKey(): string
            {
                return $this->id;
            }

            public function getMorphClass(): string
            {
                return 'bench_identity';
            }
        };

        $permissions = BenchmarkFixtures::permissionNames();
        $roles       = [BenchmarkFixtures::roleName()];
        $policies    = [BenchmarkFixtures::policy()];

        $this->roleResolver       = static fn (): array => $roles;
        $this->permissionResolver = static fn (): array => $permissions;
        $this->policyResolver     = static fn (): array => $policies;

        // Memo-only cache — the `store` parameter is null so reads
        // never drop past the memo tier.
        $this->memoOnly = new ResolutionCache(store: null, ttl: 0, prefix: 'bench-memo');
        $this->memoOnly->rememberRoles($this->principal, $this->roleResolver);
        $this->memoOnly->rememberPermissions($this->principal, $this->permissionResolver);

        // Persistent-tier cache — array store stands in for a
        // tag-capable production store. Prime the entries, then
        // flush the memo so every revolution exercises the
        // persistent-tier read path.
        $arrayStore      = new ArrayStore;
        $repository      = new CacheRepository($arrayStore);
        $this->persisted = new ResolutionCache(store: $repository, ttl: 0, prefix: 'bench-persisted');

        $this->persisted->rememberRoles($this->principal, $this->roleResolver);
        $this->persisted->rememberPermissions($this->principal, $this->permissionResolver);
        $this->persisted->rememberPolicies($this->principal, $this->policyResolver);
        $this->persisted->flush();

        $this->forgetTarget = $this->newForgetTarget();
    }

    /**
     * Per-revolution setUp for the forget subject — a fresh cache +
     * prime so each rep flushes a populated store instead of an
     * already-empty one.
     *
     * @return void
     */
    public function setUpForget(): void
    {
        $this->setUp();
        $this->forgetTarget = $this->newForgetTarget();
    }

    /**
     * Benchmark: memo-tier hit on `rememberRoles()` — the in-memory
     * lookup every second `can()` on the same principal pays.
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
     * Benchmark: memo-tier hit on `rememberPermissions()`.
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
     * Benchmark: persistent-tier hit on `rememberPolicies()` —
     * memo miss + array-store read + `Policy::fromArray()` rehydration.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(2000)]
    public function benchRememberPoliciesPersistentHit(): void
    {
        // Flush the memo each rev so the read drops to the store —
        // otherwise the memo shortcut masks the persistent-tier cost.
        $this->persisted->flush();
        $this->persisted->rememberPolicies($this->principal, $this->policyResolver);
    }

    /**
     * Benchmark: tag-based invalidation via `forget()`. Each rev
     * flushes the memo + tag-group for the principal through the
     * shared array store.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUpForget')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(2000)]
    public function benchForgetTaggedPrincipal(): void
    {
        $this->forgetTarget->forget($this->principal);
    }

    /**
     * Build + prime a fresh cache for the forget benchmark.
     *
     * @return \SineMacula\Laravel\Authorization\Cache\ResolutionCache
     */
    private function newForgetTarget(): ResolutionCache
    {
        $arrayStore = new ArrayStore;
        $repository = new CacheRepository($arrayStore);
        $cache      = new ResolutionCache(store: $repository, ttl: 0, prefix: 'bench-forget');

        $context = new ResolutionCacheContext(roleIds: ['role-1']);

        $cache->rememberRoles($this->principal, $this->roleResolver, $context);
        $cache->rememberPermissions($this->principal, $this->permissionResolver, $context);
        $cache->rememberPolicies($this->principal, $this->policyResolver, $context);

        return $cache;
    }
}
