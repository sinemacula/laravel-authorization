<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Services\Support\RecordWriter;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Creates, renames, describes, deletes and lists permissions.
 *
 * Every write runs in one transaction on the package's connection, through the
 * permission class `authorization.models.permission` configures, so the
 * permission observer, name validation and system protection apply. A
 * permission named by a string is looked up under the package's default guard;
 * a permission model that has not been saved is refused with
 * `UnsavedRecordException`, so a change never creates one outside `create()`.
 *
 * Each method takes the actor making the call as `$actor`, a model or a
 * reference, the reads as well as the writes: null for console and system work.
 * Every event a write dispatches carries it, with one operation id the call's
 * events share, once the write commits; it is never read from the authenticated
 * user.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @SuppressWarnings("php:S1172")
 */
final class PermissionService
{
    /**
     * Create a permission. A permission given no id is given a new one.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @param  string|null  $description
     * @param  string|null  $category
     * @param  string|null  $id
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \Throwable
     */
    public function create(
        string $name,
        ?string $guard = null,
        ?string $description = null,
        ?string $category = null,
        ?string $id = null,
        Model|Reference|null $actor = null,
    ): Permission {
        $class = self::permissionClass();
        $model = new $class;

        return RecordWriter::save($actor, static fn (): Permission => $model, [
            $model->getKeyName() => $id,
            'name'               => $name,
            'guard'              => $guard,
            'description'        => $description,
            'category'           => $category,
        ]);
    }

    /**
     * Rename a permission.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  string  $name
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \Throwable
     */
    public function rename(Permission|string $permission, string $name, Model|Reference|null $actor = null): Permission
    {
        return RecordWriter::save($actor, static fn (): Permission => self::resolve($permission), ['name' => $name]);
    }

    /**
     * Set or clear a permission's description.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  string|null  $description
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \Throwable
     */
    public function describe(Permission|string $permission, ?string $description, Model|Reference|null $actor = null): Permission
    {
        return RecordWriter::save($actor, static fn (): Permission => self::resolve($permission), ['description' => $description]);
    }

    /**
     * Delete a permission, and with it every grant of it. The deleted event
     * lists every grantee that held it directly and every role that carried it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return void
     *
     * @throws \Throwable
     */
    public function delete(Permission|string $permission, Model|Reference|null $actor = null): void
    {
        RecordWriter::delete($actor, static fn (): Permission => self::resolve($permission));
    }

    /**
     * Find the permission the name answers under the guard (the package default
     * when none is given), in the order `GuardScopedLookup` ranks the rows: the
     * current tenant's before the platform's, then a guard-specific row before
     * a guard-agnostic one, then the lowest primary key.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    public function find(string $name, ?string $guard = null): Permission
    {
        return self::lookup($name, $guard);
    }

    /**
     * List the permissions the tenant scope shows, by name; with a guard, only
     * those of that guard or guard-agnostic.
     *
     * @param  string|null  $guard
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission>
     */
    public function list(?string $guard = null, Model|Reference|null $actor = null): Collection
    {
        // @phpstan-ignore staticMethod.dynamicCall
        return self::permissionClass()::query()
            ->when($guard !== null, static fn (Builder $query) => $query->where(static fn (Builder $inner) => $inner->where('guard', $guard)->orWhereNull('guard')))
            ->orderBy('name')
            ->get();
    }

    /**
     * Find the permission the name answers under the guard, through the class
     * `authorization.models.permission` configures.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    private static function lookup(string $name, ?string $guard = null): Permission
    {
        $model = GuardScopedLookup::findForGuard(self::permissionClass(), $name, $guard);

        if (!$model instanceof Permission) {
            throw new UnknownPermissionException($name);
        }

        return $model;
    }

    /**
     * Resolve a permission: a name through the configured permission class,
     * under the package's default guard; a model once it is known to be saved.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnsavedRecordException
     */
    private static function resolve(Permission|string $permission): Permission
    {
        return $permission instanceof Permission ? RecordWriter::existing('permission', $permission) : self::lookup($permission);
    }

    /**
     * Return the permission class `authorization.models.permission` configures.
     *
     * @return class-string<\SineMacula\Laravel\Authorization\Models\Permission>
     */
    private static function permissionClass(): string
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> */
        return config('authorization.models.permission', Permission::class);
    }
}
