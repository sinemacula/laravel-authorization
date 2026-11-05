<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Listeners;

use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Events\Role\PermissionGranted as RolePermissionGranted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionRevoked as RolePermissionRevoked;

/**
 * Event listener that keeps the resolution cache coherent.
 *
 * Principal-scoped identity events drop only that grantee's cached lookups via
 * `ResolutionCache::forget()`, keyed by the grantee reference the event
 * carries. Role-pivot events flush every entry tagged with the affected role,
 * keyed by its reference, on tag-capable stores (Redis, Memcached, array) and
 * fall back to an in-memory flush elsewhere.
 *
 * The events are dispatched once their write commits, so the listener runs
 * after the commit too: an invalidation never precedes the change it is for,
 * and a write that rolls back invalidates nothing. A check made inside an
 * enclosing transaction after the write may still read the cached answer until
 * that transaction commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class InvalidateResolutionCache
{
    /**
     * Create a new listener instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCache  $cache
     */
    public function __construct(

        /** Shared cache whose entries the listener invalidates. */
        private ResolutionCache $cache,
    ) {}

    /**
     * Drop the cached entries belonging to the grantee on the event.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\IdentityEvent  $event
     * @return void
     */
    public function handlePrincipalMutation(IdentityEvent $event): void
    {
        /** @var \SineMacula\Laravel\Authorization\Support\Reference $grantee */
        $grantee = $event->grantee; // @phpstan-ignore property.notFound

        $this->cache->forget($grantee);
    }

    /**
     * Invalidate cached entries affected by a role-pivot mutation.
     *
     * On a tag-capable store, `forgetRoleTags()` flushes every principal entry
     * tagged with the role — the precise inverse of the role-pivot change and
     * no collateral damage to unrelated cache entries. The in-memory memo is
     * always flushed so the same request observes the mutation even before any
     * tag flush propagates.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Authorization\Events\Role\PermissionGranted|\SineMacula\Laravel\Authorization\Events\Role\PermissionRevoked  $event
     *
     * @formatter:on
     *
     * @return void
     */
    public function handleRoleMutation(RolePermissionGranted|RolePermissionRevoked $event): void
    {
        $this->cache->flush();

        if (!$this->cache->supportsTags()) {
            return;
        }

        $this->cache->forgetRoleTags($event->role);
    }
}
