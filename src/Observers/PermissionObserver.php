<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Observers;

use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Events\Permission\PermissionCreated;
use SineMacula\Laravel\Authorization\Events\Permission\PermissionDeleted;
use SineMacula\Laravel\Authorization\Events\Permission\PermissionUpdated;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Models\Permission;
use WeakMap;

/**
 * Row-lifecycle observer for the `Permission` model.
 *
 * Translates Eloquent's native `saving` / `updating` / `created` /
 * `updated` / `deleted` events into the package's typed CRUD events
 * and enforces the tenant-columns both-or-neither invariant on save.
 * System-protection hooks (`deleting`, `updating` guard, `saved`
 * bypass reset) live in
 * `HasSystemProtection::bootHasSystemProtection()` and run
 * independently of this observer.
 *
 * Registered via `#[ObservedBy(PermissionObserver::class)]` on the
 * `Permission` model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PermissionObserver
{
    /**
     * Pre-save attribute snapshots bridging `updating` and `updated`
     * so the `PermissionUpdated` event carries a complete
     * before/after diff. Keyed by the permission instance; `WeakMap`
     * means a permission that goes out of scope before its
     * `updated` fire releases its snapshot with no manual cleanup.
     *
     * Held statically so the snapshot survives Laravel's per-event
     * observer resolution — the framework calls
     * `app()->make(self::class)->method($model)` for each hook,
     * which produces a fresh instance each time unless the observer
     * is bound as a singleton.
     *
     * @var \WeakMap<\SineMacula\Laravel\Authorization\Models\Permission, array<string, mixed>>|null
     */
    private static ?\WeakMap $snapshots = null;

    /**
     * Enforce the tenant-columns invariant before any persistence.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException
     */
    public function saving(Permission $permission): void
    {
        if (($permission->tenant_type === null) === ($permission->tenant_id === null)) {
            return;
        }

        throw new InvalidTenantColumnsException(modelKind: 'permission', missingColumn: $permission->tenant_type === null ? 'tenant_type' : 'tenant_id');
    }

    /**
     * Capture the pre-update attribute snapshot so the paired
     * `updated` hook can emit a complete before/after diff.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return void
     */
    public function updating(Permission $permission): void
    {
        $snapshot = [];

        foreach (\array_keys($permission->getDirty()) as $key) {
            $snapshot[$key] = $permission->getOriginal($key);
        }

        self::snapshots()[$permission] = $snapshot;
    }

    /**
     * Emit the typed `PermissionCreated` event.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return void
     */
    public function created(Permission $permission): void
    {
        Event::dispatch(new PermissionCreated($permission));
    }

    /**
     * Emit the typed `PermissionUpdated` event with the before/after
     * diff captured in the paired `updating` hook.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return void
     */
    public function updated(Permission $permission): void
    {
        $snapshots = self::snapshots();
        $before    = $snapshots[$permission] ?? [];

        Event::dispatch(new PermissionUpdated($permission, [
            'before' => $before,
            'after'  => $permission->getChanges(),
        ]));

        unset($snapshots[$permission]);
    }

    /**
     * Emit the typed `PermissionDeleted` event.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return void
     */
    public function deleted(Permission $permission): void
    {
        Event::dispatch(new PermissionDeleted($permission));
    }

    /**
     * Return the shared snapshot map, creating it on first access.
     *
     * @return \WeakMap<\SineMacula\Laravel\Authorization\Models\Permission, array<string, mixed>>
     */
    private static function snapshots(): \WeakMap
    {
        return self::$snapshots ??= new \WeakMap;
    }
}
