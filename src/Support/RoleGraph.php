<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Database\LiveGrants;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Reads the role hierarchy and the permissions roles hold in a fixed number of
 * queries, however many roles there are and however deep the hierarchy runs.
 * The roles a holder gets grants through, its roles and their ancestors, are
 * read the same way for its permissions and for the policies attached to those
 * roles.
 *
 * The ancestors of any number of roles take two queries: one recursive query
 * for the keys of every role above them, then one load of those roles through
 * the role model, so the tenant scope hides another tenant's roles. The chains
 * are then walked in memory. The permissions of any number of roles take one
 * query. Nothing is lazy-loaded, so the graph is read the same way under
 * `Model::preventLazyLoading()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RoleGraph
{
    /** @var string The name the recursive query gives the chain it builds. */
    private const string CHAIN = 'authorization_role_chain';

    /**
     * Return the ancestors of each role, keyed by the role's key and ordered
     * from the root down to the immediate parent.
     *
     * A parent that is missing, or that the tenant scope hides, ends the chain
     * there, as it does for a single role's `ancestors()`. A chain that returns
     * to a role it has already passed raises `RoleHierarchyCycleException`.
     * Roles without a parent cost no query.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Models\Role>  $roles
     * @return array<string, list<\SineMacula\Laravel\Authorization\Models\Role>>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function ancestorsOf(array $roles): array
    {
        $parents = [];

        foreach ($roles as $role) {
            if ($role->parent_id === null) {
                continue;
            }

            $parents[] = $role->parent_id;
        }

        $visible = self::load(\array_keys(self::links($parents)));
        $chains  = [];

        foreach ($roles as $role) {
            $chains[$role->id] = self::chain($role, $visible);
        }

        return $chains;
    }

    /**
     * Return the path of each role through which its holder gets grants, keyed
     * by the role's key: the role itself, then, when the hierarchy is enabled,
     * each ancestor from the immediate parent up to the root, as
     * `ancestorsOf()` reads them. An explained check reads where a grant came
     * from through it.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Models\Role>  $roles
     * @return array<string, list<\SineMacula\Laravel\Authorization\Models\Role>>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function pathsOf(array $roles): array
    {
        $chains = self::isHierarchyEnabled() ? self::ancestorsOf($roles) : [];
        $paths  = [];

        foreach ($roles as $role) {
            $paths[$role->id] = [$role, ...\array_reverse($chains[$role->id] ?? [])];
        }

        return $paths;
    }

    /**
     * Return the names of the permissions each of the roles with the given keys
     * still carries, keyed by the role's key, in one query through the
     * permission model, as `permissionsHeldBy()` reads them: the grants an
     * explained check tells apart by the role that carries them.
     *
     * @param  list<string>  $roleKeys
     * @return array<string, list<string>>
     */
    public static function permissionsByRole(array $roleKeys): array
    {
        if ($roleKeys === []) {
            return [];
        }

        [$query, $model, $pivot] = self::permissionQuery($roleKeys);

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
     * Return the names of every permission the roles hold, with each role's
     * ancestors' when the hierarchy is enabled.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Models\Role>  $roles
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function permissionNamesHeldBy(array $roles): array
    {
        return self::permissionsHeldBy($roles)->names;
    }

    /**
     * Return the permissions the roles hold, with each role's ancestors' when
     * the hierarchy is enabled, and the seconds until the nearest of those
     * grants expires.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Models\Role>  $roles
     * @return \SineMacula\Laravel\Authorization\Support\InheritedPermissions
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function permissionsHeldBy(array $roles): InheritedPermissions
    {
        return self::permissions(self::keysHeldBy($roles));
    }

    /**
     * Return the keys of the roles, with each role's ancestors' when the
     * hierarchy is enabled: the roles whose grants the holder of the roles
     * gets, their permissions and their policies alike.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Models\Role>  $roles
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function keysHeldBy(array $roles): array
    {
        $keys = \array_map(static fn (Role $role): string => $role->id, $roles);

        if (self::isHierarchyEnabled()) {
            foreach (self::ancestorsOf($roles) as $chain) {
                foreach ($chain as $ancestor) {
                    $keys[] = $ancestor->id;
                }
            }
        }

        return $keys;
    }

    /**
     * Return the keys of the given roles and of every role above them, each
     * with the key of its parent, in one recursive query that ignores the
     * tenant scope; with the hierarchy disabled, only the given roles, without
     * a query.
     *
     * The resolution cache pins the version of every role returned before it
     * reads their permissions through `permissionsWithin()`.
     *
     * @param  list<string>  $keys
     * @return array<string, string|null>
     */
    public static function reach(array $keys): array
    {
        return self::isHierarchyEnabled() ? self::links($keys) : \array_fill_keys($keys, null);
    }

    /**
     * Return the permissions the held roles hold, with their ancestors' when
     * the hierarchy is enabled, reading the roles `reach()` returned afresh; or
     * null when a role now has a parent `reach()` did not return, because the
     * hierarchy moved after it was read.
     *
     * @param  array<string, string|null>  $reach
     * @param  list<string>  $held
     * @return \SineMacula\Laravel\Authorization\Support\InheritedPermissions|null
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function permissionsWithin(array $reach, array $held): ?InheritedPermissions
    {
        $keys = self::keysWithin($reach, $held);

        return $keys === null ? null : self::permissions($keys);
    }

    /**
     * Return the keys of the held roles the tenant scope shows, with their
     * ancestors' when the hierarchy is enabled, reading the roles `reach()`
     * returned afresh; or null when a role now has a parent `reach()` did not
     * return, because the hierarchy moved after it was read.
     *
     * @param  array<string, string|null>  $reach
     * @param  list<string>  $held
     * @return list<string>|null
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function keysWithin(array $reach, array $held): ?array
    {
        $chains = self::chainsWithin($reach, $held);

        return $chains === null ? null : self::keysOf($chains);
    }

    /**
     * Return the chain of each held role the tenant scope shows, by its key:
     * the role, then, when the hierarchy is enabled, each ancestor from its
     * parent up to the root, reading the roles `reach()` returned afresh; or
     * null when a role now has a parent `reach()` did not return, because the
     * hierarchy moved after it was read. A resolution tracking grant usage
     * reads which role a grant came through from it.
     *
     * @param  array<string, string|null>  $reach
     * @param  list<string>  $held
     * @return array<string, list<string>>|null
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function chainsWithin(array $reach, array $held): ?array
    {
        $visible   = self::load(\array_keys($reach));
        $hierarchy = self::isHierarchyEnabled();
        $chains    = [];

        foreach ($visible as $role) {
            if ($hierarchy && $role->parent_id !== null && !\array_key_exists($role->parent_id, $reach)) {
                return null;
            }
        }

        foreach (\array_intersect($held, \array_keys($visible)) as $role) {
            $above = $hierarchy ? self::chain($visible[$role], $visible) : [];

            $chains[$role] = [$role, ...\array_reverse(\array_map(static fn (Role $ancestor): string => $ancestor->id, $above))];
        }

        return $chains;
    }

    /**
     * Return the permissions the roles of the chains carry, as
     * `permissionsWithin()` reads them, in the same one query, with the key and
     * name of each permission by the key of each role carrying it.
     *
     * @param  array<string, list<string>>  $chains
     * @return \SineMacula\Laravel\Authorization\Support\InheritedPermissions
     */
    public static function carriedWithin(array $chains): InheritedPermissions
    {
        return self::permissions(self::keysOf($chains), true);
    }

    /**
     * Return the key of every role of the chains, each held role followed by
     * its ancestors from the root down, as `keysWithin()` lists them.
     *
     * @param  array<string, list<string>>  $chains
     * @return list<string>
     */
    public static function keysOf(array $chains): array
    {
        $keys = [];

        foreach ($chains as $chain) {
            \array_push($keys, $chain[0], ...\array_reverse(\array_slice($chain, 1)));
        }

        return $keys;
    }

    /**
     * Return the permissions the roles with the given keys still carry, and the
     * seconds until the nearest of those grants expires, in one query through
     * the permission model.
     *
     * @param  list<string>  $roleKeys
     * @param  bool  $isByRole
     * @return \SineMacula\Laravel\Authorization\Support\InheritedPermissions
     */
    private static function permissions(array $roleKeys, bool $isByRole = false): InheritedPermissions
    {
        if ($roleKeys === []) {
            return new InheritedPermissions([], null, $isByRole ? [] : null);
        }

        [$query, $model, $pivot] = self::permissionQuery($roleKeys);

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
    private static function permissionQuery(array $roleKeys): array
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $class */
        $class = config('authorization.models.permission', Permission::class);

        /** @var string $pivot */
        $pivot = config('authorization.tables.role_permissions', 'role_permissions');
        $model = new $class;
        $query = $class::query()
            ->useWritePdo()
            ->join($pivot, $pivot . '.permission_id', '=', $model->getQualifiedKeyName())
            ->whereIn($pivot . '.role_id', $roleKeys);

        return [LiveGrants::only($query, $pivot), $model, $pivot];
    }

    /**
     * Return the keys of the given roles and of every role above them, each
     * with the key of its parent, in one recursive query that ignores the
     * tenant scope.
     *
     * `union` rather than `union all` drops a row the chain has already
     * produced, so a cycle in the stored hierarchy ends the recursion instead
     * of running it forever.
     *
     * @param  list<string>  $keys
     * @return array<string, string|null>
     */
    private static function links(array $keys): array
    {
        if ($keys === []) {
            return [];
        }

        $model      = new (self::roleClass());
        $connection = $model->getConnection();
        $grammar    = $connection->getQueryGrammar();
        $table      = $grammar->wrapTable($model->getTable());
        $key        = $grammar->wrap($model->getKeyName());
        $parent     = $grammar->wrap('parent_id');
        $chain      = $grammar->wrap(self::CHAIN);
        $marks      = \implode(', ', \array_map(static fn (): string => '?', $keys));

        $rows = $connection->select(
            "with recursive {$chain} ({$key}, {$parent}) as ("
                . "select {$key}, {$parent} from {$table} where {$key} in ({$marks})"
                . " union select {$table}.{$key}, {$table}.{$parent} from {$table}"
                . " inner join {$chain} on {$table}.{$key} = {$chain}.{$parent}"
                . ") select {$key}, {$parent} from {$chain}",
            $keys,
            false,
        );

        /** @var array<string, string|null> */
        return \array_column($rows, 'parent_id', $model->getKeyName());
    }

    /**
     * Load the roles with the given keys through the role model, so its global
     * scopes apply, keyed by their key.
     *
     * @param  list<string>  $keys
     * @return array<string, \SineMacula\Laravel\Authorization\Models\Role>
     */
    private static function load(array $keys): array
    {
        if ($keys === []) {
            return [];
        }

        /** @var array<string, \SineMacula\Laravel\Authorization\Models\Role> */
        return self::roleClass()::query()->useWritePdo()->whereKey($keys)->get()->keyBy('id')->all();
    }

    /**
     * Walk one role's chain through the loaded roles, from its parent upwards,
     * and return it from the root down.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  array<string, \SineMacula\Laravel\Authorization\Models\Role>  $visible
     * @return list<\SineMacula\Laravel\Authorization\Models\Role>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function chain(Role $role, array $visible): array
    {
        $chain   = [];
        $visited = [];
        $current = $role;

        while ($current->parent_id !== null && isset($visible[$current->parent_id])) {
            if (isset($visited[$current->parent_id])) {
                throw new RoleHierarchyCycleException(roleName: $role->name, proposedParentName: $visible[$current->parent_id]->name);
            }

            $visited[$current->parent_id] = true;
            $current                      = $visible[$current->parent_id];

            \array_unshift($chain, $current);
        }

        return $chain;
    }

    /**
     * Determine whether the role hierarchy is enabled.
     *
     * @return bool
     */
    private static function isHierarchyEnabled(): bool
    {
        /** @var bool */
        return config('authorization.hierarchy.enabled', true);
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
