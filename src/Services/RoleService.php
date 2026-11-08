<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Database\LiveGrants;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Role\PermissionExpiryChanged as RolePermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Role\PermissionGranted as RolePermissionGranted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionRevoked as RolePermissionRevoked;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\Support\GrantChange;
use SineMacula\Laravel\Authorization\Services\Support\RecordWriter;
use SineMacula\Laravel\Authorization\Services\Support\RolePermissionTable;
use SineMacula\Laravel\Authorization\Services\Support\StoredRecords;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
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
 * Each method takes the acting context making the call as `$actor`, the reads
 * as well as the writes: null for trusted system work, such as seeders,
 * migrations and console commands (N75). A write with an acting context is
 * delegated administration (AUTHZ-11.1): each change it makes is decided as the
 * actor, through `check()`, on the change's operation resource, inside the
 * write's transaction before anything is written, and the first refused throws
 * the decision's `AuthorizationException`, leaving nothing written. A change to
 * the role itself is decided under `authorization:role.create`, `.rename`,
 * `.update`, `.delete` or `.parent.set`; adding a permission, a new grant or a
 * changed expiry, under `authorization:permission.grant`, and removing one
 * under `authorization:permission.revoke`, each in the tenant that owns the
 * role. A sync decides a grant of each listed permission the role does not
 * carry live and a revocation of each it drops; one it carries live decides
 * nothing. A revocation by name decides each permission the role carries of
 * that name; one by model decides that permission whether the role carries it
 * or not. Every change is made only from the tenant that owns the role, a
 * platform role's from the platform, or it is refused as `administration.owner`
 * (D20). Removing a permission only narrows, so it is then allowed on its
 * action alone. Adding one, or setting or replacing the parent, hands something
 * new to every holder of the role and of the roles below it: each must be one
 * the actor administers, junior to it and not itself without
 * `authorization:administration.self` (the impact check), and the actor must be
 * able to hand out what is added, the parent's whole authority included, or it
 * is refused as the first rule that fails refuses it; a parent replaced or
 * cleared whose chain carries a deny is refused as `administration.unprovable`.
 * A role is created only junior to the actor, owned by the tenant `create()` is
 * given, else by the platform, so a tenant's administrator creates its tenant's
 * roles from that tenant's context; a rename reaches every holder as a new
 * grant would, and a role a deny reaches is never deleted (see
 * `DefinitionConstraints`). A delegated change weighs, and writes, the role as
 * stored, discarding changes to the model in hand that were not saved, and the
 * permission it adds as stored (see `StoredRecords`). A read is not decided
 * yet. Every event a write dispatches carries the operation, with the actor,
 * its mode and the actions, once the write commits; the actor is never read
 * from the authenticated user.
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
     * Create a role, owned by the tenant given, or by the platform for none. A
     * role given no id is given a new one.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @param  string|null  $description
     * @param  int|null  $rank
     * @param  string|null  $id
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    public function create(
        string $name,
        ?string $guard = null,
        ?string $description = null,
        ?int $rank = null,
        ?string $id = null,
        ?ActingContext $actor = null,
        AuthorizableTenant|Model|null $tenant = null,
    ): Role {
        $attributes = ['name' => $name, 'guard' => $guard, 'description' => $description, 'rank' => $rank];

        return RecordWriter::create($actor, PackagePermissions::ROLE_CREATE, RecordWriter::ownedBy(new (self::roleClass()), $tenant), $id, $attributes);
    }

    /**
     * Rename a role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    public function rename(Role|string $role, string $name, ?ActingContext $actor = null): Role
    {
        return RecordWriter::save($actor, PackagePermissions::ROLE_RENAME, static fn (): Role => self::resolve($role), ['name' => $name]);
    }

    /**
     * Set or clear a role's description.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  string|null  $description
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    public function describe(Role|string $role, ?string $description, ?ActingContext $actor = null): Role
    {
        return RecordWriter::save($actor, PackagePermissions::ROLE_UPDATE, static fn (): Role => self::resolve($role), ['description' => $description]);
    }

    /**
     * Delete a role, and with it every grant of it. The deleted event lists
     * every grantee that held it and every permission it carried.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return void
     *
     * @throws \Throwable
     */
    public function delete(Role|string $role, ?ActingContext $actor = null): void
    {
        RecordWriter::delete($actor, PackagePermissions::ROLE_DELETE, static fn (): Role => self::resolve($role));
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
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Role>
     */
    public function list(?string $guard = null, ?ActingContext $actor = null): Collection
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
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    public function setParent(Role|string $role, Role|string|null $parent, ?ActingContext $actor = null): Role
    {
        /** @var \SineMacula\Laravel\Authorization\Models\Role */
        $model = OperationScope::run(Operation::begin($actor, [PackagePermissions::ROLE_PARENT_SET]), static function (Operation $operation) use ($actor, $role, $parent): Role {
            $model       = self::resolve($role, null, $actor);
            $parentModel = $parent === null ? null : self::resolve($parent, $model->guard);

            $actor?->authorizeIn($operation, OperationResource::definition(PackagePermissions::ROLE_PARENT_SET, $model, ['parent' => $parentModel?->id]));

            self::roleClass()::query()
                ->withoutGlobalScope(TenantScope::class)
                ->whereKey(\array_filter([$model->getKey(), $parentModel?->getKey()], static fn (mixed $key): bool => $key !== null))
                ->orderBy($model->getKeyName())
                ->lockForUpdate()
                ->get();

            $model->parent_id = $parentModel?->id;
            $model->save();

            return $model;
        }, $actor);

        return $role instanceof Role ? StoredRecords::adopt($role, $model) : $model;
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
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function grantPermission(Role|string $role, Permission|string $permission, ?\DateTimeInterface $expiresAt = null, ?ActingContext $actor = null): GrantOutcome
    {
        $operation = Operation::begin($actor, [PackagePermissions::PERMISSION_GRANT]);

        $outcome = OperationScope::run($operation, static function (Operation $operation) use ($actor, $role, $permission, $expiresAt): GrantOutcome {
            $model = self::resolve($role, null, $actor);

            OperationScope::pins()?->lockGrantees($model);

            $target = self::permissionFor($model, $permission, $actor);

            $actor?->authorizeIn($operation, OperationResource::grant(PackagePermissions::PERMISSION_GRANT, $model, $target, self::scopeOf($model), $expiresAt));

            $model->unsetRelation('permissions');

            $change = (new RolePermissionTable($model))->grant($target->id, $expiresAt);

            OperationScope::dispatch(...self::changeEvents($operation, $model, $target, $change, $expiresAt));

            return $change->outcome;
        }, $actor);

        if ($role instanceof Role) {
            $role->unsetRelation('permissions');
        }

        return $outcome;
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
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return int
     *
     * @throws \Throwable
     */
    public function revokePermission(Role|string $role, Permission|string $permission, ?ActingContext $actor = null): int
    {
        $operation = Operation::begin($actor, [PackagePermissions::PERMISSION_REVOKE]);

        $revoked = OperationScope::run($operation, static function (Operation $operation) use ($actor, $role, $permission): int {
            $model = self::resolve($role, null, $actor);

            OperationScope::pins()?->lockGrantees($model);

            $held = self::heldPermissionIds($model);

            /** @var non-empty-list<\SineMacula\Laravel\Authorization\Models\Permission> $candidates */
            $candidates = \is_string($permission) ? GrantTarget::PERMISSION->named($permission, $model->guard) : [self::permissionFor($model, $permission, $actor)];
            $revoked    = \array_values(\array_filter($candidates, static fn (Permission $target): bool => \in_array($target->id, $held, true)));
            $checked    = $revoked === [] ? [$candidates[0]] : $revoked;

            $scope = self::scopeOf($model);

            $revoke = static fn (Permission $target): OperationResource => OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, $model, $target, $scope);

            $actor?->authorizeIn($operation, ...\array_map($revoke, $checked));

            $model->unsetRelation('permissions');
            $model->permissions()->detach(\array_map(static fn (Permission $target): string => $target->id, $revoked));

            OperationScope::dispatch(...\array_map(static fn (Permission $target): RolePermissionRevoked => self::revokedEvent($operation, $model, $target), $revoked));

            return \count($revoked);
        }, $actor);

        if ($role instanceof Role) {
            $role->unsetRelation('permissions');
        }

        return $revoked;
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
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    public function syncPermissions(Role|string $role, array $permissions, ?\DateTimeInterface $expiresAt = null, ?ActingContext $actor = null): SyncResult
    {
        $operation = Operation::begin($actor, [PackagePermissions::PERMISSION_GRANT, PackagePermissions::PERMISSION_REVOKE]);

        /** @var \SineMacula\Laravel\Authorization\Services\SyncResult */
        $result = OperationScope::run($operation, static function (Operation $operation) use ($actor, $role, $permissions, $expiresAt): SyncResult {
            $model = self::resolve($role, null, $actor);

            // The role's chain and what it carries are locked before they are
            // read, so a permission the sync keeps as carried is carried until
            // the write, never one revoked meanwhile and written back.
            OperationScope::pins()?->lockGrantees($model);

            $held    = self::heldPermissionIds($model);
            $desired = self::desired($model, $permissions, $held, $actor);
            $revoked = \array_values(\array_diff($held, \array_map(static fn (Permission $target): string => $target->id, $desired)));
            $table   = new RolePermissionTable($model);
            $now     = Carbon::now('UTC');
            $changed = [];
            $events  = [];

            $live = $actor === null ? [] : self::heldPermissionIds($model, $now);

            $actor?->authorizeIn($operation, ...self::syncChanges($model, $desired, $revoked, $expiresAt, $live));

            $model->unsetRelation('permissions');
            $model->permissions()->detach($revoked);

            foreach ($desired as $target) {
                $change = $table->rearm($target->id, $expiresAt, $now);
                $events = [...$events, ...self::changeEvents($operation, $model, $target, $change, $expiresAt)];

                // A permission decided as carried live is never written back:
                // one gone by the write was not what was decided.
                if ($change->outcome !== GrantOutcome::UNCHANGED && \in_array($target->id, $live, true)) {
                    throw DependencyChangedException::rows('role_permissions');
                }

                $changed[$change->outcome->value][] = $target->id;
            }

            /** @var list<\SineMacula\Laravel\Authorization\Models\Permission> $removed */
            $removed = GrantTarget::PERMISSION->find($revoked);

            foreach ($removed as $target) {
                $events[] = self::revokedEvent($operation, $model, $target);
            }

            OperationScope::dispatch(...$events);

            return new SyncResult($changed[GrantOutcome::GRANTED->value] ?? [], $changed[GrantOutcome::REARMED->value] ?? [], $revoked);
        }, $actor);

        if ($role instanceof Role) {
            $role->unsetRelation('permissions');
        }

        return $result;
    }

    /**
     * Return the changes a sync of the role's permissions makes, each to be
     * decided before any is written: a grant of each listed permission the role
     * does not carry live (a new one, or one whose grant has expired and is
     * re-armed), the same permission kept unchanged for each it does carry
     * live, as read at the sync's instant once the role's rows are locked, and
     * a revocation of each it carries and the list leaves out. The sync re-arms
     * as of the same instant, so a permission decided as kept unchanged is
     * never re-armed; a sync that changes nothing at all decides its revocation
     * unchanged, so its action is still decided.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Models\Permission>  $desired
     * @param  list<string>  $revoked
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  list<string>  $live
     * @return non-empty-list<\SineMacula\Laravel\Authorization\Administration\OperationResource>
     */
    private static function syncChanges(Role $role, array $desired, array $revoked, ?\DateTimeInterface $expiresAt, array $live): array
    {
        $scope   = self::scopeOf($role);
        $changes = [];

        foreach ($desired as $target) {
            $changes[] = \in_array($target->id, $live, true)
                ? OperationResource::unchanged(PackagePermissions::PERMISSION_GRANT, $role, $target, $scope)
                : OperationResource::grant(PackagePermissions::PERMISSION_GRANT, $role, $target, $scope, $expiresAt);
        }

        /** @var list<\SineMacula\Laravel\Authorization\Models\Permission> $removed */
        $removed = GrantTarget::PERMISSION->find($revoked);

        foreach ($removed as $target) {
            $changes[] = OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, $role, $target, $scope);
        }

        return $changes === [] ? [OperationResource::unchanged(PackagePermissions::PERMISSION_REVOKE, $role, null, $scope)] : $changes;
    }

    /**
     * Return the scope a change to the role's permissions is decided in: the
     * tenant that owns the role, or the platform.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     */
    private static function scopeOf(Role $role): GrantScope
    {
        return new GrantScope(Reference::tenantOf($role));
    }

    /**
     * Resolve the permissions a sync lists for the role, each once: a model as
     * given; for a name, every permission of it the role carries, else the one
     * the lookup ranks first.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  array<int, mixed>  $permissions
     * @param  list<string>  $held
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return array<array-key, \SineMacula\Laravel\Authorization\Models\Permission>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    private static function desired(Role $role, array $permissions, array $held, ?ActingContext $actor): array
    {
        $desired = [];

        foreach ($permissions as $permission) {
            /** @var list<\SineMacula\Laravel\Authorization\Models\Permission> $targets */
            $targets = \is_string($permission) ? GrantTarget::PERMISSION->heldOrFirst($permission, $role->guard, $held) : [self::permissionFor($role, $permission, $actor)];

            foreach ($targets as $target) {
                $desired[$target->id] = $target;
            }
        }

        return $desired;
    }

    /**
     * Return the keys of the permissions the role carries, read from the role
     * permission pivot: every one, or, at the instant given, those it carries
     * live then.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \Illuminate\Support\Carbon|null  $liveAt
     * @return list<string>
     */
    private static function heldPermissionIds(Role $role, ?Carbon $liveAt = null): array
    {
        $pivot = $role->permissions()->newPivotQuery();
        $keys  = ($liveAt === null ? $pivot : LiveGrants::only($pivot, $role->permissions()->getTable(), $liveAt))->pluck('permission_id')->all();

        return \array_values(\array_map(static fn (mixed $key): string => \is_scalar($key) ? (string) $key : '', $keys));
    }

    /**
     * Resolve a permission for the role: a name under the role's guard, else
     * the package default; a model once it is known to be a saved permission,
     * its row as stored for a delegated change (see `StoredRecords`), so the
     * change is weighed on the name the row holds.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  mixed  $permission
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    private static function permissionFor(Role $role, mixed $permission, ?ActingContext $actor = null): Permission
    {
        /** @var \SineMacula\Laravel\Authorization\Models\Permission $resolved */
        $resolved = GrantTarget::PERMISSION->resolve($permission, $role->guard);

        return $actor === null || \is_string($permission) ? $resolved : StoredRecords::of('permission', $resolved);
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
     * change never creates a role and an unsaved parent never clears one. A
     * model a delegated change edits is first read again as stored, a fresh
     * instance each try, discarding changes to it not saved, so the change is
     * weighed on, and writes, the row as stored, and a try the concurrency
     * protocol rolls back never leaves the next one a model it changed.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  string|null  $guard
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnsavedRecordException
     */
    private static function resolve(Role|string $role, ?string $guard = null, ?ActingContext $actor = null): Role
    {
        if (!$role instanceof Role) {
            return self::lookup($role, $guard);
        }

        $model = RecordWriter::existing('role', $role);

        return $actor === null ? $model : StoredRecords::of('role', $model);
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
