<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;

/**
 * `PolicyResolver` decorator that routes `policiesFor()` through the resolution
 * cache.
 *
 * Wraps any existing resolver — the default, a tenant-scoped variant, or a
 * consumer-supplied implementation — and consults the cache before delegating
 * to the inner resolver. The inner resolver stays responsible for gathering
 * strategy; this decorator only adds the memoisation and persistent-cache
 * tiers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class CachingPolicyResolver implements PolicyResolver
{
    /**
     * Create a new caching resolver instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\PolicyResolver  $inner
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCache  $cache
     */
    public function __construct(

        /** Wrapped resolver that actually gathers policies on a cold miss. */
        private readonly PolicyResolver $inner,

        /** Shared cache holding memoised and optionally persisted results. */
        private readonly ResolutionCache $cache,

    ) {}

    /**
     * @param  object  $principal
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    #[\Override]
    public function policiesFor(object $principal): array
    {
        return $this->cache->rememberPolicies(
            $principal,
            fn (): array => $this->inner->policiesFor($principal),
        );
    }
}
