<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Registrars;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionGranted as IdentityPermissionGranted;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionRevoked as IdentityPermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyAttached as IdentityPolicyAttached;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyDetached as IdentityPolicyDetached;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned as IdentityRoleAssigned;
use SineMacula\Laravel\Authorization\Events\Identity\RoleRevoked as IdentityRoleRevoked;
use SineMacula\Laravel\Authorization\Events\Role\PermissionGranted as RolePermissionGranted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionRevoked as RolePermissionRevoked;
use SineMacula\Laravel\Authorization\Listeners\InvalidateResolutionCache;

/**
 * Wire the package's event listeners onto the application dispatcher.
 *
 * Owns the resolution-cache invalidator, fired on every mutation to a
 * principal's cached lookups (role / permission / policy attach/detach/expiry,
 * plus role-permission mutations that cascade to every principal carrying the
 * role).
 *
 * No request-boundary listener is needed: the request and job state (the
 * resolution cache, the last decision, the resolvers and the resolved tenant)
 * is bound with `scoped()`, which Laravel's queue worker forgets before each
 * job and Octane builds afresh on each request's sandbox.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EventListenerRegistrar
{
    /**
     * Create a new registrar instance.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     */
    public function __construct(

        /** Framework container consulted for dispatcher binding. */
        private Application $app,
    ) {}

    /**
     * Register every event listener this package wires by default.
     *
     * @return void
     */
    public function register(): void
    {
        $this->registerCacheInvalidationListeners();
    }

    /**
     * Wire the invalidation listener to every event that mutates a principal's
     * cached lookups.
     *
     * @return void
     */
    private function registerCacheInvalidationListeners(): void
    {
        if (!$this->app->bound(Dispatcher::class)) {
            return;
        }

        $dispatcher = $this->app->make(Dispatcher::class);

        $principalEvents = [
            IdentityRoleAssigned::class,
            IdentityRoleRevoked::class,
            IdentityPermissionGranted::class,
            IdentityPermissionRevoked::class,
            IdentityPolicyAttached::class,
            IdentityPolicyDetached::class,
        ];

        foreach ($principalEvents as $event) {
            $dispatcher->listen($event, [InvalidateResolutionCache::class, 'handlePrincipalMutation']);
        }

        foreach ([RolePermissionGranted::class, RolePermissionRevoked::class] as $event) {
            $dispatcher->listen($event, [InvalidateResolutionCache::class, 'handleRoleMutation']);
        }
    }
}
