<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Repositories;

use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\PolicyRepository;

/**
 * `PolicyRepository` decorator that routes `policiesFor()` through
 * the resolution cache.
 *
 * Wraps any existing repository — the default, a tenant-scoped
 * variant, or a consumer-supplied implementation — and consults
 * the cache before delegating to the inner repository. The inner
 * repository stays responsible for gathering strategy; this
 * decorator only adds the memoisation and persistent-cache tiers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class CachingPolicyRepository implements PolicyRepository
{
    /**
     * Create a new caching repository instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\PolicyRepository  $inner
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCache  $cache
     */
    public function __construct(

        /** Wrapped repository that actually gathers policies on a cold miss. */
        private readonly PolicyRepository $inner,

        /** Shared cache holding memoised and optionally persisted gathering results. */
        private readonly ResolutionCache $cache,

    ) {}

    /**
     * {@inheritdoc}
     */
    public function policiesFor(object $principal): array
    {
        return $this->cache->rememberPolicies(
            $principal,
            fn (): array => $this->inner->policiesFor($principal),
        );
    }
}
