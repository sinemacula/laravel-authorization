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
 *   `RolePermissionRevoked`) have no reverse index into the set of
 *   identities carrying the role; walking the pivot to find them
 *   would cost more than the cache saves. The listener calls
 *   `flush()` instead, which clears the in-memory tier across
 *   every principal. The persistent tier is left alone — the
 *   granular entries expire on TTL or on the next principal-scoped
 *   event for each affected identity.
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
     * Flush the in-memory tier on a role-pivot mutation.
     *
     * @param  \SineMacula\Laravel\Authorization\Events\RolePermissionGranted|\SineMacula\Laravel\Authorization\Events\RolePermissionRevoked  $event
     * @return void
     */
    public function handleRoleMutation(
        RolePermissionGranted|RolePermissionRevoked $event,
    ): void {
        $this->cache->flush();
    }
}
