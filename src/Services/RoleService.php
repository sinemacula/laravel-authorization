<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Role\PermissionGranted as RolePermissionGranted;
use SineMacula\Laravel\Authorization\Events\Role\PermissionRevoked as RolePermissionRevoked;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\Support\RecordWriter;

/**
 * Creates, renames, describes, re-parents, deletes and lists roles, and grants,
 * revokes and syncs the permissions a role carries.
 *
 * Every write runs in one transaction on the package's connection, through the
 * role class `authorization.models.role` configures, so the role observer, name
 * validation and system protection apply. A role named by a string is looked up
 * under the package's default guard; a permission named by a string under the
 * role's own guard, else the default.
 *
 * Setting a parent locks the role and the parent, and the observer walks the
 * parent's ancestors under the same lock and outside the tenant scope, so two
 * concurrent re-parentings cannot close a cycle between them, and a cycle
 * through another tenant's role is refused as well.
 *
 * Granting a permission the role carries changes nothing, and a concurrent
 * duplicate never surfaces a unique-constraint violation. The role permission
 * events are dispatched once the transaction has returned, and only for a write
 * that changed something.
 *
 * Each method takes the acting subject as `$actor`: null for console and system
 * work.
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
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    public function create(string $name, ?string $guard = null, ?string $description = null, ?int $rank = null, ?string $id = null, ?object $actor = null): Role
    {
        $class = self::roleClass();
        $model = new $class;

        return RecordWriter::save(static fn (): Role => $model, [
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
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    public function rename(Role|string $role, string $name, ?object $actor = null): Role
    {
        return RecordWriter::save(static fn (): Role => self::resolve($role), ['name' => $name]);
    }

    /**
     * Set or clear a role's description.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  string|null  $description
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    public function describe(Role|string $role, ?string $description, ?object $actor = null): Role
    {
        return RecordWriter::save(static fn (): Role => self::resolve($role), ['description' => $description]);
    }

    /**
     * Delete a role, and with it every grant of it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  object|null  $actor
     * @return void
     *
     * @throws \Throwable
     */
    public function delete(Role|string $role, ?object $actor = null): void
    {
        RecordWriter::delete(static fn (): Role => self::resolve($role));
    }

    /**
     * List the roles the tenant scope shows, by name; with a guard, only those
     * of that guard or guard-agnostic.
     *
     * @param  string|null  $guard
     * @return \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Role>
     */
    public function list(?string $guard = null): Collection
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
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    public function setParent(Role|string $role, Role|string|null $parent, ?object $actor = null): Role
    {
        /** @var \SineMacula\Laravel\Authorization\Models\Role */
        return AuthorizationConnection::connection()->transaction(static function () use ($role, $parent): Role {
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
     * Grant a permission to a role. A permission the role carries already is
     * reported as unchanged.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function grantPermission(Role|string $role, Permission|string $permission, ?object $actor = null): GrantOutcome
    {
        /** @var list<\SineMacula\Laravel\Authorization\Events\Role\PermissionGranted> $events */
        $events = AuthorizationConnection::connection()->transaction(static function () use ($role, $permission): array {
            $model  = self::resolve($role);
            $target = self::permissionFor($model, $permission);

            return self::writeAttachment($model, $target) ? [new RolePermissionGranted($model, $target)] : [];
        });

        self::dispatch($events);

        return $events === [] ? GrantOutcome::UNCHANGED : GrantOutcome::GRANTED;
    }

    /**
     * Revoke a permission from a role, and return how many were revoked: none
     * when the role did not carry it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  object|null  $actor
     * @return int
     *
     * @throws \Throwable
     */
    public function revokePermission(Role|string $role, Permission|string $permission, ?object $actor = null): int
    {
        /** @var list<\SineMacula\Laravel\Authorization\Events\Role\PermissionRevoked> $events */
        $events = AuthorizationConnection::connection()->transaction(static function () use ($role, $permission): array {
            $model  = self::resolve($role);
            $target = self::permissionFor($model, $permission);

            $model->unsetRelation('permissions');

            return $model->permissions()->detach($target->id) > 0 ? [new RolePermissionRevoked($model, $target)] : [];
        });

        self::dispatch($events);

        return \count($events);
    }

    /**
     * Replace a role's permissions with the given ones.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Permission|string>  $permissions
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    public function syncPermissions(Role|string $role, array $permissions, ?object $actor = null): SyncResult
    {
        $events = [];

        /** @var \SineMacula\Laravel\Authorization\Services\SyncResult $result */
        $result = AuthorizationConnection::connection()->transaction(static function () use ($role, $permissions, &$events): SyncResult {
            $model    = self::resolve($role);
            $relation = $model->permissions();
            $desired  = self::desired($model, $permissions);
            $held     = \array_map(static fn (mixed $key): string => \is_scalar($key) ? (string) $key : '', $relation->newPivotQuery()->pluck('permission_id')->all());
            $revoked  = \array_values(\array_diff($held, \array_map(static fn (Permission $target): string => $target->id, $desired)));
            $granted  = [];

            $relation->detach($revoked);

            foreach ($desired as $target) {
                if (!self::writeAttachment($model, $target)) {
                    continue;
                }

                $granted[] = $target->id;
                $events[]  = new RolePermissionGranted($model, $target);
            }

            foreach ($relation->getRelated()->newQuery()->withoutGlobalScope(TenantScope::class)->whereKey($revoked)->get() as $target) {
                $events[] = new RolePermissionRevoked($model, $target);
            }

            return new SyncResult($granted, [], $revoked);
        });

        self::dispatch($events);

        return $result;
    }

    /**
     * Resolve the permissions a sync lists for the role, each once.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  array<int, mixed>  $permissions
     * @return array<array-key, \SineMacula\Laravel\Authorization\Models\Permission>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    private static function desired(Role $role, array $permissions): array
    {
        $desired = [];

        foreach ($permissions as $permission) {
            $target               = self::permissionFor($role, $permission);
            $desired[$target->id] = $target;
        }

        return $desired;
    }

    /**
     * Attach the permission to the role unless it carries it, and report
     * whether it was attached. The attachment goes through the role permission
     * pivot, so guard parity is enforced, inside a savepoint, so a concurrent
     * duplicate rolls back only the attachment.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return bool
     *
     * @throws \Throwable
     */
    private static function writeAttachment(Role $role, Permission $permission): bool
    {
        $role->unsetRelation('permissions');

        $relation = $role->permissions();

        if ($relation->newPivotQuery()->where('permission_id', $permission->id)->exists()) {
            return false;
        }

        try {
            AuthorizationConnection::connection()->transaction(static fn () => $relation->attach($permission->id));
        } catch (UniqueConstraintViolationException) {
            return false;
        }

        return true;
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
     * Resolve a role: a name through the configured role class, under the given
     * guard or the package default; a model as given.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  string|null  $guard
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    private static function resolve(Role|string $role, ?string $guard = null): Role
    {
        return $role instanceof Role ? $role : self::roleClass()::resolveByName($role, $guard);
    }

    /**
     * Dispatch the call's events, once its transaction has returned.
     *
     * @param  list<object>  $events
     * @return void
     */
    private static function dispatch(array $events): void
    {
        foreach ($events as $event) {
            Event::dispatch($event);
        }
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
