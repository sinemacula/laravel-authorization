<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Services\Support\RecordWriter;

/**
 * Creates, renames, describes, deletes and lists permissions.
 *
 * Every write runs in one transaction on the package's connection, through the
 * permission class `authorization.models.permission` configures, so the
 * permission observer, name validation and system protection apply. A
 * permission named by a string is looked up under the package's default guard.
 *
 * Each method takes the acting subject as `$actor`: null for console and system
 * work.
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
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \Throwable
     */
    public function create(string $name, ?string $guard = null, ?string $description = null, ?string $category = null, ?string $id = null, ?object $actor = null): Permission
    {
        $class = self::permissionClass();
        $model = new $class;

        return RecordWriter::save(static fn (): Permission => $model, [
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
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \Throwable
     */
    public function rename(Permission|string $permission, string $name, ?object $actor = null): Permission
    {
        return RecordWriter::save(static fn (): Permission => self::resolve($permission), ['name' => $name]);
    }

    /**
     * Set or clear a permission's description.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  string|null  $description
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \Throwable
     */
    public function describe(Permission|string $permission, ?string $description, ?object $actor = null): Permission
    {
        return RecordWriter::save(static fn (): Permission => self::resolve($permission), ['description' => $description]);
    }

    /**
     * Delete a permission, and with it every grant of it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  object|null  $actor
     * @return void
     *
     * @throws \Throwable
     */
    public function delete(Permission|string $permission, ?object $actor = null): void
    {
        RecordWriter::delete(static fn (): Permission => self::resolve($permission));
    }

    /**
     * List the permissions the tenant scope shows, by name; with a guard, only
     * those of that guard or guard-agnostic.
     *
     * @param  string|null  $guard
     * @return \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission>
     */
    public function list(?string $guard = null): Collection
    {
        // @phpstan-ignore staticMethod.dynamicCall
        return self::permissionClass()::query()
            ->when($guard !== null, static fn (Builder $query) => $query->where(static fn (Builder $inner) => $inner->where('guard', $guard)->orWhereNull('guard')))
            ->orderBy('name')
            ->get();
    }

    /**
     * Resolve a permission: a name through the configured permission class,
     * under the package's default guard; a model as given.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    private static function resolve(Permission|string $permission): Permission
    {
        return $permission instanceof Permission ? $permission : self::permissionClass()::resolveByName($permission);
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
