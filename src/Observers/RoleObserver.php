<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Observers;

use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Events\Role\Created as RoleCreated;
use SineMacula\Laravel\Authorization\Events\Role\Deleted as RoleDeleted;
use SineMacula\Laravel\Authorization\Events\Role\Updated as RoleUpdated;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Row-lifecycle observer for the `Role` model.
 *
 * Translates Eloquent's native `saving` / `updating` / `created` /
 * `updated` / `deleted` events into the package's typed CRUD events,
 * enforces the tenant-columns both-or-neither invariant on save, and
 * guards against hierarchy cycles before a `parent_id` change is
 * persisted. System-protection hooks (`deleting`, `updating` guard,
 * `saved` bypass reset) live in
 * `HasSystemProtection::bootHasSystemProtection()` and run
 * independently of this observer.
 *
 * Registered via `#[ObservedBy(RoleObserver::class)]` on the `Role`
 * model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RoleObserver
{
    /** @var \WeakMap<\SineMacula\Laravel\Authorization\Models\Role, array<string, mixed>>|null Pre-update snapshots keyed by model. */
    private static ?\WeakMap $snapshots = null;

    /**
     * Enforce the tenant-columns invariant and the hierarchy
     * cycle-detection guard before any persistence.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public function saving(Role $role): void
    {
        $this->assertTenantColumnsInvariant($role);

        if ($role->parent_id !== null) {
            $this->assertNoHierarchyCycle($role);
        }
    }

    /**
     * Capture the pre-update attribute snapshot so the paired
     * `updated` hook can emit a complete before/after diff.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     */
    public function updating(Role $role): void
    {
        $snapshot = [];

        foreach (\array_keys($role->getDirty()) as $key) {
            $snapshot[$key] = $role->getOriginal($key);
        }

        self::snapshots()[$role] = $snapshot;
    }

    /**
     * Emit the typed `RoleCreated` event.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     */
    public function created(Role $role): void
    {
        Event::dispatch(new RoleCreated($role));
    }

    /**
     * Emit the typed `RoleUpdated` event with the before/after diff
     * captured in the paired `updating` hook.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     */
    public function updated(Role $role): void
    {
        $snapshots = self::snapshots();
        $before    = $snapshots[$role] ?? [];

        Event::dispatch(new RoleUpdated($role, [
            'before' => $before,
            'after'  => $role->getChanges(),
        ]));

        unset($snapshots[$role]);
    }

    /**
     * Emit the typed `RoleDeleted` event.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     */
    public function deleted(Role $role): void
    {
        Event::dispatch(new RoleDeleted($role));
    }

    /**
     * Return the shared snapshot map, creating it on first access.
     *
     * @return \WeakMap<\SineMacula\Laravel\Authorization\Models\Role, array<string, mixed>>
     */
    private static function snapshots(): \WeakMap
    {
        return self::$snapshots ??= new \WeakMap;
    }

    /**
     * Enforce the both-or-neither tenant ownership invariant on
     * save.
     *
     * A row with only one of `tenant_type` / `tenant_id` set would
     * be invisible to the `TenantScope` global filter and to
     * `scopeForTenant` / `scopeGlobalOnly`, silently orphaning the
     * data. Fail loudly on save.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException
     */
    private function assertTenantColumnsInvariant(Role $role): void
    {
        if (($role->tenant_type === null) === ($role->tenant_id === null)) {
            return;
        }

        throw new InvalidTenantColumnsException(modelKind: 'role', missingColumn: $role->tenant_type === null ? 'tenant_type' : 'tenant_id');
    }

    /**
     * Guard the saving role against hierarchy cycles. Covers the
     * self-referential case and the "proposed parent is already a
     * descendant" case for existing rows whose `parent_id` changed.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private function assertNoHierarchyCycle(Role $role): void
    {
        if ($role->exists && $role->parent_id === $role->getKey()) {
            throw new RoleHierarchyCycleException(roleName: $role->name, proposedParentName: $role->name);
        }

        if (!$role->exists || !$role->isDirty('parent_id')) {
            return;
        }

        foreach ($role->descendants() as $descendant) {
            if ($descendant->getKey() === $role->parent_id) {
                $proposedParent = Role::query()->find($role->parent_id);
                $proposedName   = $proposedParent !== null ? $proposedParent->name : $role->parent_id;

                throw new RoleHierarchyCycleException(roleName: $role->name, proposedParentName: $proposedName);
            }
        }
    }
}
