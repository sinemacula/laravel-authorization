<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Observers;

use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Role\Created as RoleCreated;
use SineMacula\Laravel\Authorization\Events\Role\Deleted as RoleDeleted;
use SineMacula\Laravel\Authorization\Events\Role\Updated as RoleUpdated;
use SineMacula\Laravel\Authorization\Exceptions\ReservedRoleNameException;
use SineMacula\Laravel\Authorization\Exceptions\RoleHasChildrenException;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\Support\RecordChanges;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\RecordOwner;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\RoleParity;

/**
 * Row-lifecycle observer for the `Role` model.
 *
 * Translates Eloquent's native `saving` / `updating` / `created` / `updated` /
 * `deleting` / `deleted` events into the package's typed record events,
 * enforces the tenant-columns both-or-neither invariant and the reserved system
 * role names on save, and guards against hierarchy cycles before a `parent_id`
 * change is persisted. System-protection hooks (`deleting`, `updating` guard,
 * `saved` bypass reset) live in
 * `HasSystemProtection::bootHasSystemProtection()` and run independently of
 * this observer.
 *
 * The events are snapshots of plain values, dispatched once the write commits
 * on the package's connection, and carry the operation the write belongs to:
 * the management service call that made it, with its actor, or a write of its
 * own with no actor. A delete reads, before the row goes, every grantee that
 * held the role and every permission it carried.
 *
 * Registered via `#[ObservedBy(RoleObserver::class)]` on the `Role` model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RoleObserver
{
    /**
     * Enforce the owner rules (see `RecordOwner`), the reserved system role
     * names, parity with the parent, children and permissions (see
     * `RoleParity`) and the hierarchy cycle-detection guard before any
     * persistence.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OwnerChangedException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\ParentGuardMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\ReservedRoleNameException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public function saving(Role $role): void
    {
        RecordOwner::assertValid($role, 'role');
        $this->assertNoSystemRoleNameIsShared($role);
        $this->assertParity($role);

        if ($role->parent_id === null) {
            return;
        }

        $this->assertNoHierarchyCycle($role);
    }

    /**
     * Capture the changed fields' values before the update, so the paired
     * `updated` hook can report a complete before/after diff.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     */
    public function updating(Role $role): void
    {
        RecordChanges::capture($role);
    }

    /**
     * Report the role created.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     */
    public function created(Role $role): void
    {
        OperationScope::dispatch(new RoleCreated(
            OperationScope::current($role),
            Reference::of($role),
            $role->name,
            $role->guard,
            Reference::tenantOf($role),
            $role->getAttribute('is_system') === true,
        ));
    }

    /**
     * Report the role updated, with the before/after diff captured in the
     * paired `updating` hook.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     */
    public function updated(Role $role): void
    {
        OperationScope::dispatch(new RoleUpdated(
            OperationScope::current($role),
            Reference::of($role),
            $role->name,
            $role->guard,
            Reference::tenantOf($role),
            RecordChanges::diff($role),
        ));
    }

    /**
     * Refuse to delete a role with children (D18), then read, before the row
     * goes, every grantee that holds the role and every permission it carries,
     * which the delete takes with it.
     *
     * The children are read outside the tenant scope, so a child the current
     * tenant cannot see still holds the delete back.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHasChildrenException
     */
    public function deleting(Role $role): void
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $roleClass */
        $roleClass = ModelClasses::get('role');

        /** @var list<string> $children */
        $children = $roleClass::query()->withoutGlobalScope(TenantScope::class)->where('parent_id', $role->id)->orderBy('name')->pluck('name')->all();

        if ($children !== []) {
            throw new RoleHasChildrenException($role->name, $children);
        }

        RecordChanges::hold($role, [
            'grantees'    => GrantTarget::ROLE->holders(Reference::of($role)->id),
            'permissions' => RecordChanges::linked($role->permissions()),
        ]);
    }

    /**
     * Report the role deleted, with the grantees and permissions read in the
     * paired `deleting` hook, and detach the policies attached to it, each
     * reported as detached. The role is a grantee of its policies, a morph with
     * no foreign key, so the delete does not take those rows with it. With no
     * grant service bound, the delete throws rather than leaving them silently.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    public function deleted(Role $role): void
    {
        $grants = GrantService::instance() ?? throw new \LogicException('The authorization grant service is not bound; register the package\'s service provider.');

        $grants->revokeAll(Reference::of($role));

        /** @var array{grantees?: list<\SineMacula\Laravel\Authorization\Support\Reference>, permissions?: list<\SineMacula\Laravel\Authorization\Support\Reference>} $held */
        $held = RecordChanges::release($role);

        OperationScope::dispatch(new RoleDeleted(
            OperationScope::current($role),
            Reference::of($role),
            $role->name,
            $role->guard,
            Reference::tenantOf($role),
            $held['grantees']    ?? [],
            $held['permissions'] ?? [],
        ));
    }

    /**
     * Refuse a parent the role cannot sit under, and, when the role's guard
     * changes, a child or permission it no longer suits.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\ParentGuardMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException
     */
    private function assertParity(Role $role): void
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $roleClass */
        $roleClass = ModelClasses::get('role');
        $query     = $roleClass::query()->withoutGlobalScope(TenantScope::class);
        $parent    = $role->parent_id === null || !$role->isDirty(['parent_id', 'guard']) ? null : (clone $query)->find($role->parent_id);

        if ($parent instanceof Role) {
            RoleParity::assertUnder($role, $parent);
        }

        if (!$role->exists || !$role->isDirty('guard')) {
            return;
        }

        foreach ($query->where('parent_id', $role->id)->get() as $child) {
            RoleParity::assertUnder($child, $role);
        }

        // Every permission the role carries, an expired grant included, since a
        // re-armed grant keeps its row.
        /** @var list<string> $permissions */
        $permissions = $role->permissions()->newPivotQuery()->pluck('permission_id')->all();

        /** @var list<\SineMacula\Laravel\Authorization\Models\Permission> $carried */
        $carried = GrantTarget::PERMISSION->find($permissions);

        foreach ($carried as $permission) {
            RoleParity::assertCarries($role, $permission);
        }
    }

    /**
     * Refuse a tenant role that shares its name with a platform system role
     * under a guard both answer, and a platform system role whose name a tenant
     * role already holds.
     *
     * A check by name matches any held role of that name, so a tenant's role
     * named after a platform system role would pass every name check written
     * for the system role. Two guards both answer when they are equal or either
     * row is guard-agnostic. The check runs only when one of the columns it
     * reads changes.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\ReservedRoleNameException
     */
    private function assertNoSystemRoleNameIsShared(Role $role): void
    {
        $isTenantOwned = $role->tenant_type !== null;

        if (!$role->isDirty(['name', 'guard', 'tenant_type', 'tenant_id', 'is_system']) || (!$isTenantOwned && !$role->is_system)) {
            return;
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $roleClass */
        $roleClass = ModelClasses::get('role');
        $guard     = $role->guard;

        // @phpstan-ignore staticMethod.dynamicCall
        $shared = $roleClass::query()
            ->withoutGlobalScopes()
            ->where('name', $role->name)
            ->when($role->exists, static fn (Builder $query) => $query->whereKeyNot($role->getKey()))
            ->when(
                $isTenantOwned,
                static fn (Builder $query) => $query->whereNull('tenant_type')->where('is_system', true),
                static fn (Builder $query) => $query->whereNotNull('tenant_type'),
            )
            ->when($guard !== null, static fn (Builder $query) => $query->where(static fn (Builder $inner) => $inner->where('guard', $guard)->orWhereNull('guard')))
            ->exists();

        if ($shared) {
            throw new ReservedRoleNameException($role->name);
        }
    }

    /**
     * Guard the saving role against hierarchy cycles when its parent changes.
     *
     * Walks up from the proposed parent, locking each ancestor for update and
     * reading it outside the tenant scope, until the chain ends. Reaching the
     * role itself means the parent is the role or one of its descendants; a
     * chain that loops without reaching the role is corrupt. Both are refused.
     * Inside the role service's transaction, which has locked the role and the
     * parent first, the locks hold until commit, so two concurrent
     * re-parentings cannot close a cycle between them, and a cycle through
     * another tenant's role is seen.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private function assertNoHierarchyCycle(Role $role): void
    {
        if (!$role->isDirty('parent_id')) {
            return;
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $roleClass */
        $roleClass = ModelClasses::get('role');
        $current   = $role->parent_id;
        $parent    = null;
        $visited   = [];

        while ($current !== null) {
            if ($current === $role->getKey() || isset($visited[$current])) {
                throw new RoleHierarchyCycleException(roleName: $role->name, proposedParentName: $parent ?? $role->name);
            }

            $visited[$current] = true;

            /** @var \SineMacula\Laravel\Authorization\Models\Role|null $ancestor */
            $ancestor = $roleClass::query()->withoutGlobalScope(TenantScope::class)->whereKey($current)->lockForUpdate()->first();
            $parent ??= $ancestor?->name;
            $current = $ancestor?->parent_id;
        }
    }
}
