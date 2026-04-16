<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Listeners;

use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Events\IdentityPermissionGranted;
use SineMacula\Laravel\Authorization\Events\IdentityPermissionRevoked;
use SineMacula\Laravel\Authorization\Events\IdentityPolicyAttached;
use SineMacula\Laravel\Authorization\Events\IdentityPolicyDetached;
use SineMacula\Laravel\Authorization\Events\IdentityRoleAssigned;
use SineMacula\Laravel\Authorization\Events\IdentityRoleRevoked;
use SineMacula\Laravel\Authorization\Events\RolePermissionGranted;
use SineMacula\Laravel\Authorization\Events\RolePermissionRevoked;

/**
 * Event listener that keeps the resolution cache coherent.
 *
 * Two invalidation strategies:
 *
 * - **Principal-scoped events** (`IdentityRoleAssigned`,
 *   `IdentityRoleRevoked`, `IdentityPermissionGranted`,
 *   `IdentityPermissionRevoked`, `IdentityPolicyAttached`,
 *   `IdentityPolicyDetached`) carry the authorizable that changed. The
 *   listener calls `ResolutionCache::forget($authorizable)` so
 *   only that principal's cached lookups are dropped.
 * - **Role-pivot events** (`RolePermissionGranted`,
 *   `RolePermissionRevoked`) have no reverse index in a plain
 *   cache store, so the listener branches on store capability:
 *   tag-capable stores (Redis, Memcached, the Laravel array
 *   store) flush every entry tagged with the affected role via
 *   `forgetRoleTags()`; non-tag stores (File, Database) fall
 *   back to `flush()`, which clears only the in-memory tier and
 *   leaves persistent entries to expire on TTL or on the next
 *   principal-scoped event. This closes ISSUES.md #68 for the
 *   common production stores and preserves the prior behaviour
 *   everywhere else.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidateResolutionCache
{
    /**
     * Create a new listener instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCache  $cache
     */
    public function __construct(

        /** Shared cache whose entries the listener invalidates. */
        private readonly ResolutionCache $cache,

    ) {}

    /**
     * Drop the cached entries belonging to the authorizable on
     * the event.
     *
     * @param  \SineMacula\Laravel\Authorization\Events\IdentityPermissionGranted|\SineMacula\Laravel\Authorization\Events\IdentityPermissionRevoked|\SineMacula\Laravel\Authorization\Events\IdentityPolicyAttached|\SineMacula\Laravel\Authorization\Events\IdentityPolicyDetached|\SineMacula\Laravel\Authorization\Events\IdentityRoleAssigned|\SineMacula\Laravel\Authorization\Events\IdentityRoleRevoked  $event
     * @return void
     */
    public function handlePrincipalMutation(
        IdentityPermissionGranted|IdentityPermissionRevoked|IdentityPolicyAttached|IdentityPolicyDetached|IdentityRoleAssigned|IdentityRoleRevoked $event,
    ): void {
        $this->cache->forget($event->authorizable);
    }

    /**
     * Invalidate cached entries affected by a role-pivot mutation.
     *
     * On a tag-capable store, `forgetRoleTags()` flushes every
     * principal entry tagged with the role — the precise
     * inverse of the role-pivot change and no collateral damage
     * to unrelated cache entries. The in-memory memo is always
     * flushed so the same request observes the mutation even
     * before any tag flush propagates.
     *
     * @param  \SineMacula\Laravel\Authorization\Events\RolePermissionGranted|\SineMacula\Laravel\Authorization\Events\RolePermissionRevoked  $event
     * @return void
     */
    public function handleRoleMutation(
        RolePermissionGranted|RolePermissionRevoked $event,
    ): void {
        $this->cache->flush();

        if ($this->cache->supportsTags()) {
            $this->cache->forgetRoleTags($event->role);
        }
    }
}
