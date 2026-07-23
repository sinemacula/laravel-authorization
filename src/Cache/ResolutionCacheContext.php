<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

/**
 * Context carried alongside a cache-remember call.
 *
 * Bundles the optional cache-metadata parameters that the `remember*` methods
 * on `ResolutionCache` need beyond the core `(principal, resolver)` pair.
 * Adding future knobs (per-call tag prefix, cache-driver override, hit-only
 * flag) extends this object instead of widening every remember-method
 * signature.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ResolutionCacheContext
{
    /**
     * Create a new cache context instance.
     *
     * @param  int|null  $maxTtl
     * @param  array<int, string>  $roleIds
     */
    public function __construct(

        /** Upper TTL bound derived from the nearest upcoming grant expiry; null means unconstrained. */
        public ?int $maxTtl = null,

        /** Role IDs this entry depends on; tagged on capable stores for role-scoped invalidation. */
        public array $roleIds = [],
    ) {}
}
