<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Observers;

use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Permission\Created as PermissionCreated;
use SineMacula\Laravel\Authorization\Events\Permission\Deleted as PermissionDeleted;
use SineMacula\Laravel\Authorization\Events\Permission\Updated as PermissionUpdated;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Observers\Support\RecordChanges;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\RecordOwner;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\RoleParity;

/**
 * Row-lifecycle observer for the `Permission` model.
 *
 * Translates Eloquent's native `saving` / `updating` / `created` / `updated` /
 * `deleting` / `deleted` events into the package's typed record events and
 * enforces the tenant-columns both-or-neither invariant on save.
 * System-protection hooks (`deleting`, `updating` guard, `saved` bypass reset)
 * live in `HasSystemProtection::bootHasSystemProtection()` and run
 * independently of this observer.
 *
 * The events are snapshots of plain values, dispatched once the write commits
 * on the package's connection, and carry the operation the write belongs to:
 * the management service call that made it, with its actor, or a write of its
 * own with no actor. A delete reads, before the row goes, every grantee that
 * held the permission directly and every role that carried it.
 *
 * Registered via `#[ObservedBy(PermissionObserver::class)]` on the `Permission`
 * model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PermissionObserver
{
    /**
     * Enforce the owner rules before any persistence (see `RecordOwner`), and,
     * when the permission's guard changes, its parity with every role that
     * carries it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OwnerChangedException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException
     */
    public function saving(Permission $permission): void
    {
        RecordOwner::assertValid($permission, 'permission');

        if (!$permission->exists || !$permission->isDirty('guard')) {
            return;
        }

        // A role naming half a tenant applies nowhere, so it is passed over:
        // nothing is linked here.
        foreach ($permission->roles()->withoutGlobalScope(TenantScope::class)->get() as $role) {
            RoleParity::assertCarries($role, $permission, false);
        }
    }

    /**
     * Capture the changed fields' values before the update, so the paired
     * `updated` hook can report a complete before/after diff.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return void
     */
    public function updating(Permission $permission): void
    {
        RecordChanges::capture($permission);
    }

    /**
     * Report the permission created.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return void
     */
    public function created(Permission $permission): void
    {
        OperationScope::dispatch(new PermissionCreated(
            OperationScope::current($permission),
            Reference::of($permission),
            $permission->name,
            $permission->guard,
            Reference::tenantOf($permission),
            $permission->getAttribute('is_system') === true,
        ));
    }

    /**
     * Report the permission updated, with the before/after diff captured in the
     * paired `updating` hook.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return void
     */
    public function updated(Permission $permission): void
    {
        OperationScope::dispatch(new PermissionUpdated(
            OperationScope::current($permission),
            Reference::of($permission),
            $permission->name,
            $permission->guard,
            Reference::tenantOf($permission),
            RecordChanges::diff($permission),
        ));
    }

    /**
     * Read, before the row goes, every grantee that holds the permission
     * directly and every role that carries it, which the delete takes with it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return void
     */
    public function deleting(Permission $permission): void
    {
        RecordChanges::hold($permission, [
            'grantees' => GrantTarget::PERMISSION->holders(Reference::of($permission)->id),
            'roles'    => RecordChanges::linked($permission->roles()),
        ]);
    }

    /**
     * Report the permission deleted, with the grantees and roles read in the
     * paired `deleting` hook.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return void
     */
    public function deleted(Permission $permission): void
    {
        /** @var array{grantees?: list<\SineMacula\Laravel\Authorization\Support\Reference>, roles?: list<\SineMacula\Laravel\Authorization\Support\Reference>} $held */
        $held = RecordChanges::release($permission);

        OperationScope::dispatch(new PermissionDeleted(
            OperationScope::current($permission),
            Reference::of($permission),
            $permission->name,
            $permission->guard,
            Reference::tenantOf($permission),
            $held['grantees'] ?? [],
            $held['roles']    ?? [],
        ));
    }
}
