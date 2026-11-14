<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\LiveGrants;

/**
 * Reads the permissions roles still carry, in one query through the permission
 * model, for `RoleGraph`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RolePermissions
{
    /**
     * Return the names of the permissions each of the roles with the given keys
     * still carries, keyed by the role's key.
     *
     * @param  list<string>  $roleKeys
     * @return array<string, list<string>>
     */
    public static function namesByRole(array $roleKeys): array
    {
        if ($roleKeys === []) {
            return [];
        }

        [$query, $model, $pivot] = self::query($roleKeys);

        /** @var list<array{role_id: string, name: string}> $rows */
        $rows = $query->toBase()
            ->distinct()
            ->get([$pivot . '.role_id as role_id', $model->qualifyColumn('name') . ' as name'])
            ->map(static fn (object $row): array => (array) $row)
            ->all();

        $carried = [];

        foreach ($rows as $row) {
            $carried[$row['role_id']][] = $row['name'];
        }

        return $carried;
    }

    /**
     * Return the permissions the roles with the given keys still carry, and the
     * seconds until the nearest of those grants expires, with the key and name
     * of each by the key of each role carrying it when asked.
     *
     * @param  list<string>  $roleKeys
     * @param  bool  $isByRole
     * @return \SineMacula\Laravel\Authorization\Support\InheritedPermissions
     */
    public static function carried(array $roleKeys, bool $isByRole = false): InheritedPermissions
    {
        if ($roleKeys === []) {
            return new InheritedPermissions([], null, $isByRole ? [] : null);
        }

        [$query, $model, $pivot] = self::query($roleKeys);

        $columns = [$model->qualifyColumn('name') . ' as name', $pivot . '.expires_at as expires_at'];

        if ($isByRole) {
            \array_push($columns, $pivot . '.role_id as role_id', $model->getQualifiedKeyName() . ' as permission_id');
        }

        /** @var list<array{name: string, expires_at: string|null, role_id?: int|string, permission_id?: int|string}> $rows */
        $rows = $query
            ->toBase()
            ->distinct()
            ->get($columns)
            ->map(static fn (object $row): array => (array) $row)
            ->all();

        $now     = Carbon::now()->getTimestamp();
        $names   = [];
        $nearest = null;

        foreach ($rows as $row) {
            $names[$row['name']] = $row['name'];

            if ($row['expires_at'] === null) {
                continue;
            }

            $nearest = \min($nearest ?? \PHP_INT_MAX, Carbon::parse($row['expires_at'], 'UTC')->getTimestamp() - $now);
        }

        return new InheritedPermissions(\array_values($names), $nearest, $isByRole ? self::byRole($rows) : null);
    }

    /**
     * Return the key and name of each permission the rows read, by the key of
     * the role carrying it, each once.
     *
     * @param  list<array{name: string, expires_at: string|null, role_id?: int|string, permission_id?: int|string}>  $rows
     * @return array<string, list<array{id: string, name: string}>>
     */
    private static function byRole(array $rows): array
    {
        $carried = [];

        foreach ($rows as $row) {
            $role = (string) ($row['role_id'] ?? '');
            $id   = (string) ($row['permission_id'] ?? '');

            $carried[$role][$id] = ['id' => $id, 'name' => $row['name']];
        }

        return \array_map(\array_values(...), $carried);
    }

    /**
     * Return the query for the live grants of permissions to the roles with the
     * given keys, through the permission model, with the model and the grant
     * table it joins.
     *
     * @param  list<string>  $roleKeys
     * @return array{\Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authorization\Models\Permission>, \SineMacula\Laravel\Authorization\Models\Permission, string}
     */
    private static function query(array $roleKeys): array
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $class */
        $class = ModelClasses::get('permission');

        $pivot = TableNames::get('role_permissions');
        $model = new $class;
        $query = $class::query()
            ->useWritePdo()
            ->join($pivot, $pivot . '.permission_id', '=', $model->getQualifiedKeyName())
            ->whereIn($pivot . '.role_id', $roleKeys);

        return [LiveGrants::only($query, $pivot), $model, $pivot];
    }
}
