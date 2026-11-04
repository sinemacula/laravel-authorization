<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
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
 * Both tiers are bounded by the nearest expiry among the policies the principal
 * attaches itself (through `HasPolicies`), so a temporary policy stops applying
 * when it lapses, within one request or job too. Once the in-memory entry has
 * lapsed the principal reads its attachments afresh.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CachingPolicyResolver implements PolicyResolver
{
    /**
     * Create a new caching resolver instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\PolicyResolver  $inner
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCache  $cache
     */
    public function __construct(

        /** Wrapped resolver that actually gathers policies on a cold miss. */
        private PolicyResolver $inner,

        /** Shared cache holding memoised and optionally persisted results. */
        private ResolutionCache $cache,
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
            new ResolutionCacheContext(maxTtl: $this->nearestPolicyExpiry($principal)),
        );
    }

    /**
     * Return the seconds until the nearest policy the principal attaches itself
     * lapses, or null when it attaches none that expire or cannot attach
     * policies at all. The attachments are read afresh once the cached entry
     * has lapsed.
     *
     * @param  object  $principal
     * @return int|null
     */
    private function nearestPolicyExpiry(object $principal): ?int
    {
        if (!\method_exists($principal, 'secondsUntilPolicyExpiry')) {
            return null;
        }

        /** @var int|null */
        return $principal->secondsUntilPolicyExpiry($this->cache->lapsed('policies', $principal));
    }
}
