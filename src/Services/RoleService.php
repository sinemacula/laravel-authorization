<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Role\PermissionExpiryChanged as RolePermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Role\PermissionGranted as RolePermissionGranted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionRevoked as RolePermissionRevoked;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\Support\GrantChange;
use SineMacula\Laravel\Authorization\Services\Support\RecordWriter;
use SineMacula\Laravel\Authorization\Services\Support\RolePermissionTable;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Creates, renames, describes, re-parents, deletes and lists roles, and grants,
 * revokes and syncs the permissions a role carries.
 *
 * Every write runs in one transaction on the package's connection, through the
 * role class `authorization.models.role` configures, so the role observer, name
 * validation and system protection apply. A role named by a string is looked up
 * under the package's default guard; a permission named by a string under the
 * role's own guard, else the default. A role model that has not been saved, as
 * the role or as the parent, is refused with `UnsavedRecordException`.
 *
 * Setting a parent locks the role and the parent, and the observer walks the
 * parent's ancestors under the same lock and outside the tenant scope, so two
 * concurrent re-parentings cannot close a cycle between them, and a cycle
 * through another tenant's role is refused as well.
 *
 * A role's grant of a permission may carry an expiry, after which it no longer
 * counts. Granting a permission the role carries with the same expiry changes
 * nothing, and a concurrent duplicate never surfaces a unique-constraint
 * violation. The role and role permission events are dispatched once the write
 * commits, on the package's connection, and only for a write that changed
 * something.
 *
 * Each method takes the actor making the call as `$actor`, a model or a
 * reference, the reads as well as the writes: null for console and system work.
 * Every event a write dispatches carries it, with one operation id the call's
 * events share; it is never read from the authenticated user.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @SuppressWarnings("php:S1172")
 */
final class RoleService
{
    use HasContainerInstance;

    /**
     * Create a role. A role given no id is given a new one.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @param  string|null  $description
     * @param  int|null  $rank
     * @param  string|null  $id
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    public function create(string $name, ?string $guard = null, ?string $description = null, ?int $rank = null, ?string $id = null, Model|Reference|null $actor = null): Role
    {
        $class = self::roleClass();
        $model = new $class;

        return RecordWriter::save($actor, static fn (): Role => $model, [
            $model->getKeyName() => $id,
            'name'               => $name,
            'guard'              => $guard,
            'description'        => $description,
            'rank'               => $rank,
        ]);
    }

    /**
     * Rename a role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  string  $name
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    public function rename(Role|string $role, string $name, Model|Reference|null $actor = null): Role
    {
        return RecordWriter::save($actor, static fn (): Role => self::resolve($role), ['name' => $name]);
    }

    /**
     * Set or clear a role's description.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  string|null  $description
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    public function describe(Role|string $role, ?string $description, Model|Reference|null $actor = null): Role
    {
        return RecordWriter::save($actor, static fn (): Role => self::resolve($role), ['description' => $description]);
    }

    /**
     * Delete a role, and with it every grant of it. The deleted event lists
     * every grantee that held it and every permission it carried.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return void
     *
     * @throws \Throwable
     */
    public function delete(Role|string $role, Model|Reference|null $actor = null): void
    {
        RecordWriter::delete($actor, static fn (): Role => self::resolve($role));
    }

    /**
     * Find the role the name answers under the guard (the package default when
     * none is given), in the order `GuardScopedLookup` ranks the rows: the
     * current tenant's before the platform's, then a guard-specific row before
     * a guard-agnostic one, then the lowest primary key.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    public function find(string $name, ?string $guard = null): Role
    {
        return self::lookup($name, $guard);
    }

    /**
     * List the roles the tenant scope shows, by name; with a guard, only those
     * of that guard or guard-agnostic.
     *
     * @param  string|null  $guard
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Role>
     */
    public function list(?string $guard = null, Model|Reference|null $actor = null): Collection
    {
        // @phpstan-ignore staticMethod.dynamicCall
        return self::roleClass()::query()
            ->when($guard !== null, static fn (Builder $query) => $query->where(static fn (Builder $inner) => $inner->where('guard', $guard)->orWhereNull('guard')))
            ->orderBy('name')
            ->get();
    }

    /**
     * Set or clear a role's parent.
     *
     * The role and the parent are locked first, in key order, then the parent's
     * ancestors as the observer walks them, outside the tenant scope. A parent
     * that is the role itself, or one of its descendants, throws
     * `RoleHierarchyCycleException`. A parent named by a string is looked up
     * under the role's guard.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string|null  $parent
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    public function setParent(Role|string $role, Role|string|null $parent, Model|Reference|null $actor = null): Role
    {
        /** @var \SineMacula\Laravel\Authorization\Models\Role */
        return OperationScope::run(Operation::begin($actor), static function () use ($role, $parent): Role {
            $model       = self::resolve($role);
            $parentModel = $parent === null ? null : self::resolve($parent, $model->guard);

            self::roleClass()::query()
                ->withoutGlobalScope(TenantScope::class)
                ->whereKey(\array_filter([$model->getKey(), $parentModel?->getKey()], static fn (mixed $key): bool => $key !== null))
                ->orderBy($model->getKeyName())
                ->lockForUpdate()
                ->get();

            $model->parent_id = $parentModel?->id;
            $model->save();

            return $model;
        });
    }

    /**
     * Grant a permission to a role, until the given expiry or forever.
     *
     * Granting a permission the role carries with the same expiry changes
     * nothing; a permission whose grant has expired is re-armed with the new
     * expiry, and a live grant given a different expiry has it changed.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function grantPermission(Role|string $role, Permission|string $permission, ?\DateTimeInterface $expiresAt = null, Model|Reference|null $actor = null): GrantOutcome
    {
        return OperationScope::run(Operation::begin($actor), static function (Operation $operation) use ($role, $permission, $expiresAt): GrantOutcome {
            $model  = self::resolve($role);
            $target = self::permissionFor($model, $permission);

            $model->unsetRelation('permissions');

            $change = (new RolePermissionTable($model))->grant($target->id, $expiresAt);

            OperationScope::dispatch(...self::changeEvents($operation, $model, $target, $change, $expiresAt));

            return $change->outcome;
        });
    }

    /**
     * Revoke a permission from a role, and return how many were revoked: none
     * when the role did not carry it.
     *
     * A name revokes every permission of that name the role carries, under the
     * role's guard or guard-agnostic, whichever tenant or the platform owns it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return int
     *
     * @throws \Throwable
     */
    public function revokePermission(Role|string $role, Permission|string $permission, Model|Reference|null $actor = null): int
    {
        return OperationScope::run(Operation::begin($actor), static function (Operation $operation) use ($role, $permission): int {
            $model = self::resolve($role);
            $held  = self::heldPermissionIds($model);

            /** @var list<\SineMacula\Laravel\Authorization\Models\Permission> $candidates */
            $candidates = \is_string($permission) ? GrantTarget::PERMISSION->named($permission, $model->guard) : [self::permissionFor($model, $permission)];
            $revoked    = \array_values(\array_filter($candidates, static fn (Permission $target): bool => \in_array($target->id, $held, true)));

            $model->unsetRelation('permissions');
            $model->permissions()->detach(\array_map(static fn (Permission $target): string => $target->id, $revoked));

            OperationScope::dispatch(...\array_map(static fn (Permission $target): RolePermissionRevoked => self::revokedEvent($operation, $model, $target), $revoked));

            return \count($revoked);
        });
    }

    /**
     * Replace a role's permissions with the given ones.
     *
     * A permission the role carries is kept as it is; one whose grant has
     * expired is re-armed with the given expiry, and one the role did not carry
     * is granted until it, or forever.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Permission|string>  $permissions
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    public function syncPermissions(Role|string $role, array $permissions, ?\DateTimeInterface $expiresAt = null, Model|Reference|null $actor = null): SyncResult
    {
        /** @var \SineMacula\Laravel\Authorization\Services\SyncResult */
        return OperationScope::run(Operation::begin($actor), static function (Operation $operation) use ($role, $permissions, $expiresAt): SyncResult {
            $model   = self::resolve($role);
            $held    = self::heldPermissionIds($model);
            $desired = self::desired($model, $permissions, $held);
            $revoked = \array_values(\array_diff($held, \array_map(static fn (Permission $target): string => $target->id, $desired)));
            $table   = new RolePermissionTable($model);
            $changed = [];
            $events  = [];

            $model->unsetRelation('permissions');
            $model->permissions()->detach($revoked);

            foreach ($desired as $target) {
                $change = $table->rearm($target->id, $expiresAt);
                $events = [...$events, ...self::changeEvents($operation, $model, $target, $change, $expiresAt)];

                $changed[$change->outcome->value][] = $target->id;
            }

            /** @var list<\SineMacula\Laravel\Authorization\Models\Permission> $removed */
            $removed = GrantTarget::PERMISSION->find($revoked);

            foreach ($removed as $target) {
                $events[] = self::revokedEvent($operation, $model, $target);
            }

            OperationScope::dispatch(...$events);

            return new SyncResult($changed[GrantOutcome::GRANTED->value] ?? [], $changed[GrantOutcome::REARMED->value] ?? [], $revoked);
        });
    }

    /**
     * Resolve the permissions a sync lists for the role, each once: a model as
     * given; for a name, every permission of it the role carries, else the one
     * the lookup ranks first.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  array<int, mixed>  $permissions
     * @param  list<string>  $held
     * @return array<array-key, \SineMacula\Laravel\Authorization\Models\Permission>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    private static function desired(Role $role, array $permissions, array $held): array
    {
        $desired = [];

        foreach ($permissions as $permission) {
            /** @var list<\SineMacula\Laravel\Authorization\Models\Permission> $targets */
            $targets = \is_string($permission) ? GrantTarget::PERMISSION->heldOrFirst($permission, $role->guard, $held) : [self::permissionFor($role, $permission)];

            foreach ($targets as $target) {
                $desired[$target->id] = $target;
            }
        }

        return $desired;
    }

    /**
     * Return the keys of the permissions the role carries, read from the role
     * permission pivot.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return list<string>
     */
    private static function heldPermissionIds(Role $role): array
    {
        $keys = $role->permissions()->newPivotQuery()->pluck('permission_id')->all();

        return \array_values(\array_map(static fn (mixed $key): string => \is_scalar($key) ? (string) $key : '', $keys));
    }

    /**
     * Resolve a permission for the role: a name under the role's guard, else
     * the package default; a model once it is known to be a saved permission.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  mixed  $permission
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    private static function permissionFor(Role $role, mixed $permission): Permission
    {
        /** @var \SineMacula\Laravel\Authorization\Models\Permission */
        return GrantTarget::PERMISSION->resolve($permission, $role->guard);
    }

    /**
     * Find the role the name answers under the guard, through the class
     * `authorization.models.role` configures.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    private static function lookup(string $name, ?string $guard = null): Role
    {
        $model = GuardScopedLookup::findForGuard(self::roleClass(), $name, $guard);

        if (!$model instanceof Role) {
            throw new UnknownRoleException($name);
        }

        return $model;
    }

    /**
     * Resolve a role: a name through the configured role class, under the given
     * guard or the package default; a model once it is known to be saved, so a
     * change never creates a role and an unsaved parent never clears one.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  string|null  $guard
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnsavedRecordException
     */
    private static function resolve(Role|string $role, ?string $guard = null): Role
    {
        return $role instanceof Role ? RecordWriter::existing('role', $role) : self::lookup($role, $guard);
    }

    /**
     * Build the events a grant of a permission to the role dispatches: none
     * when it changed nothing, the granted event for a new grant, and also the
     * expiry-changed event for a re-armed grant or a changed expiry.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @param  \SineMacula\Laravel\Authorization\Services\Support\GrantChange  $change
     * @param  \DateTimeInterface|null  $expiresAt
     * @return list<\SineMacula\Laravel\Authorization\Events\Role\PermissionExpiryChanged|\SineMacula\Laravel\Authorization\Events\Role\PermissionGranted>
     */
    private static function changeEvents(Operation $operation, Role $role, Permission $permission, GrantChange $change, ?\DateTimeInterface $expiresAt): array
    {
        $grant     = [$operation, Reference::of($role), $role->name, Reference::of($permission), $permission->name, Reference::tenantOf($role)];
        $expiresAt = UtcDateTime::toUtc($expiresAt)?->toImmutable();
        $granted   = new RolePermissionGranted(...[...$grant, $expiresAt]);

        return match ($change->outcome) {
            GrantOutcome::UNCHANGED => [],
            GrantOutcome::GRANTED   => [$granted],
            default                 => [$granted, new RolePermissionExpiryChanged(...[...$grant, $change->previousExpiresAt?->toImmutable(), $expiresAt])],
        };
    }

    /**
     * Build the event the revocation of a permission from the role dispatches.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return \SineMacula\Laravel\Authorization\Events\Role\PermissionRevoked
     */
    private static function revokedEvent(Operation $operation, Role $role, Permission $permission): RolePermissionRevoked
    {
        return new RolePermissionRevoked($operation, Reference::of($role), $role->name, Reference::of($permission), $permission->name, Reference::tenantOf($role));
    }

    /**
     * Return the role class `authorization.models.role` configures.
     *
     * @return class-string<\SineMacula\Laravel\Authorization\Models\Role>
     */
    private static function roleClass(): string
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> */
        return config('authorization.models.role', Role::class);
    }
}
