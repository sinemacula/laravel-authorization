<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console\Support;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\DeclaredPermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * The package's rows a Spatie import maps onto: the role or permission it
 * reuses, and the changes it would make to the permissions of a system role it
 * reuses, which only `forceSystem()` unlocks, so the import cannot make them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SpatieRows
{
    /**
     * Return the row of the configured model with the name and guard that the
     * owner holds, the platform when null, which a re-run reuses, or null when
     * there is none.
     *
     * @param  'permission'|'role'  $model
     * @param  string  $name
     * @param  string|null  $guard
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $owner
     * @return \Illuminate\Database\Eloquent\Model|null
     */
    public static function owned(string $model, string $name, ?string $guard, ?Reference $owner): ?Model
    {
        /** @var class-string<\Illuminate\Database\Eloquent\Model> $class */
        $class = ModelClasses::get($model);
        $query = $class::query()->withoutGlobalScope(TenantScope::class)->where('name', $name)->where('guard', $guard);

        if ($owner === null) {
            return TenantChain::whereNullTenant($query, 'tenant_type', 'tenant_id')->first();
        }

        return $query->where('tenant_type', $owner->type)->where('tenant_id', $owner->id)->first();
    }

    /**
     * Return, by role name, the permissions the import would grant to each
     * system role it reuses, or grant again without an expiry: each Spatie role
     * permission whose role maps to a system role that does not hold the
     * permission forever. A permission the import skips is left out.
     *
     * @param  array<array-key, array<array-key, mixed>>  $roles
     * @param  array<array-key, array<array-key, mixed>>  $permissions
     * @param  array<array-key, array<array-key, mixed>>  $rolePermissions
     * @param  \Closure(array<array-key, mixed>): (\SineMacula\Laravel\Authorization\Support\Reference|null)  $tenantOf
     * @return array<string, list<string>>
     */
    public static function systemRoleChanges(array $roles, array $permissions, array $rolePermissions, \Closure $tenantOf): array
    {
        $system  = self::systemRoles($roles, $tenantOf);
        $targets = $system === [] ? [] : self::permissions($permissions);
        $changes = [];

        foreach ($rolePermissions as $row) {
            $role                = $system[self::text($row['role_id'] ?? null)]        ?? null;
            [$name, $permission] = $targets[self::text($row['permission_id'] ?? null)] ?? [null, null];

            if ($role === null || $name === null || ($permission !== null && self::holdsForever($role, $permission))) {
                continue;
            }

            $changes[$role->name][] = $name;
        }

        return $changes;
    }

    /**
     * Return the system roles the Spatie roles map to, by Spatie id.
     *
     * @param  array<array-key, array<array-key, mixed>>  $roles
     * @param  \Closure(array<array-key, mixed>): (\SineMacula\Laravel\Authorization\Support\Reference|null)  $tenantOf
     * @return array<string, \SineMacula\Laravel\Authorization\Models\Role>
     */
    private static function systemRoles(array $roles, \Closure $tenantOf): array
    {
        $system = [];

        foreach ($roles as $row) {
            $role = self::owned('role', self::text($row['name'] ?? null), self::guardOf($row), $tenantOf($row));

            if (!$role instanceof Role || !$role->is_system) {
                continue;
            }

            $system[self::text($row['id'] ?? null)] = $role;
        }

        return $system;
    }

    /**
     * Return each Spatie permission the import keeps, by Spatie id: its name,
     * and the permission it reuses, or null for one it would create.
     *
     * @param  array<array-key, array<array-key, mixed>>  $permissions
     * @return array<string, array{string, \SineMacula\Laravel\Authorization\Models\Permission|null}>
     */
    private static function permissions(array $permissions): array
    {
        $targets = [];

        /** @var \SineMacula\Laravel\Authorization\Contracts\ActionCatalogue $catalogue */
        $catalogue = Container::getInstance()->make(ActionCatalogue::class);

        foreach ($permissions as $row) {
            $name = self::text($row['name'] ?? null);

            if (!Permission::isValidAuthorizationName($name) || \str_contains($name, '*') || !DeclaredPermissions::covers($name, $catalogue)) {
                continue;
            }

            $permission = self::owned('permission', $name, self::guardOf($row), null);

            $targets[self::text($row['id'] ?? null)] = [$name, $permission instanceof Permission ? $permission : null];
        }

        return $targets;
    }

    /**
     * Determine whether the role holds the permission with no expiry, so
     * granting it again changes nothing.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return bool
     */
    private static function holdsForever(Role $role, Permission $permission): bool
    {
        return $role->permissions()->newPivotQuery()->where('permission_id', $permission->getKey())->whereNull('expires_at')->exists();
    }

    /**
     * Return a Spatie row's guard, or null for none.
     *
     * @param  array<array-key, mixed>  $row
     * @return string|null
     */
    private static function guardOf(array $row): ?string
    {
        $guard = $row['guard_name'] ?? null;

        return \is_string($guard) ? $guard : null;
    }

    /**
     * Return a value read from a Spatie row as a string: a scalar as itself,
     * anything else as empty.
     *
     * @param  mixed  $value
     * @return string
     */
    private static function text(mixed $value): string
    {
        return \is_scalar($value) ? (string) $value : '';
    }
}
