<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Registrars;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
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
 * Owns two listener registrations:
 *
 * - The resolution-cache invalidator, fired on every mutation to a principal's
 *   cached lookups (role / permission / policy attach/detach/expiry, plus
 *   role-permission mutations that cascade to every principal carrying the
 *   role).
 * - An Octane request-boundary reset for the `LastDecisionStore` singleton. The
 *   store is a container singleton, so under Octane (or RoadRunner / Swoole /
 *   FrankenPHP) the slot survives across requests and would otherwise leak the
 *   previous request's decision into the next one's `lastDecision()` accessor.
 *   The listener is wired only when Octane's `RequestTerminated` event class is
 *   present — keeping the package free of a hard Octane dependency while
 *   auto-resetting when Octane is installed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class EventListenerRegistrar
{
    /**
     * Create a new registrar instance.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     */
    public function __construct(

        /** Framework container consulted for dispatcher binding. */
        private readonly Application $app,
    ) {}

    /**
     * Register every event listener this package wires by default.
     *
     * @return void
     */
    public function register(): void
    {
        $this->registerCacheInvalidationListeners();
        $this->registerOctaneResetListener();
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

    /**
     * Wire an Octane request-boundary listener that clears the
     * `LastDecisionStore` between requests.
     *
     * @return void
     */
    private function registerOctaneResetListener(): void
    {
        $event = 'Laravel\Octane\Events\RequestTerminated';

        if (!\class_exists($event) || !$this->app->bound(Dispatcher::class)) {
            return;
        }

        $dispatcher = $this->app->make(Dispatcher::class);

        $app = $this->app;

        $dispatcher->listen($event, static function () use ($app): void {
            if (!$app->bound(LastDecisionStore::class)) {
                return;
            }

            $app->make(LastDecisionStore::class)->reset();
        });
    }
}
