<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Services\Support\RecordWriter;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;

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
 * Each method takes the acting context making the call as `$actor`, the reads
 * as well as the writes: null for trusted system work, such as seeders,
 * migrations and console commands (N75). A write with an acting context is
 * delegated administration (AUTHZ-11.1): it is decided as the actor, through
 * `check()`, on the definition's operation resource, under
 * `authorization:permission.create`, `.rename`, `.update` or `.delete`, inside
 * its transaction before anything is written, and refused with the decision's
 * `AuthorizationException` when it is not allowed. A change is made only from
 * the tenant that owns the permission, a platform permission's from the
 * platform (`administration.owner`, D20). Creating, describing and deleting a
 * permission widen no one; renaming one re-grants it to every holder under the
 * new name, so each holder must be one the actor administers and the actor must
 * be able to hand out the new name (see `DefinitionConstraints`). A read is not
 * decided yet. Every event a write dispatches carries the operation, with the
 * actor, its mode and the action, once the write commits; the actor is never
 * read from the authenticated user.
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
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
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
        ?ActingContext $actor = null,
    ): Permission {
        $class = self::permissionClass();

        return RecordWriter::create($actor, PackagePermissions::PERMISSION_CREATE, new $class, $id, [
            'name'        => $name,
            'guard'       => $guard,
            'description' => $description,
            'category'    => $category,
        ]);
    }

    /**
     * Rename a permission.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \Throwable
     */
    public function rename(Permission|string $permission, string $name, ?ActingContext $actor = null): Permission
    {
        return RecordWriter::save($actor, PackagePermissions::PERMISSION_RENAME, static fn (): Permission => self::resolve($permission), ['name' => $name]);
    }

    /**
     * Set or clear a permission's description.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  string|null  $description
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \Throwable
     */
    public function describe(Permission|string $permission, ?string $description, ?ActingContext $actor = null): Permission
    {
        return RecordWriter::save($actor, PackagePermissions::PERMISSION_UPDATE, static fn (): Permission => self::resolve($permission), ['description' => $description]);
    }

    /**
     * Delete a permission, and with it every grant of it. The deleted event
     * lists every grantee that held it directly and every role that carried it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return void
     *
     * @throws \Throwable
     */
    public function delete(Permission|string $permission, ?ActingContext $actor = null): void
    {
        RecordWriter::delete($actor, PackagePermissions::PERMISSION_DELETE, static fn (): Permission => self::resolve($permission));
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
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission>
     */
    public function list(?string $guard = null, ?ActingContext $actor = null): Collection
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
