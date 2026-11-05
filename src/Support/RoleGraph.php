<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Reads the role hierarchy and the permissions roles hold in a fixed number of
 * queries, however many roles there are and however deep the hierarchy runs.
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
        $keys = \array_map(static fn (Role $role): string => $role->id, $roles);

        if (self::isHierarchyEnabled()) {
            foreach (self::ancestorsOf($roles) as $chain) {
                foreach ($chain as $ancestor) {
                    $keys[] = $ancestor->id;
                }
            }
        }

        return self::permissionNames($keys);
    }

    /**
     * Return the keys of the given roles and of every role above them, each
     * with the key of its parent, in one recursive query that ignores the
     * tenant scope; with the hierarchy disabled, only the given roles, without
     * a query.
     *
     * The resolution cache pins the version of every role returned before it
     * reads their permissions through `permissionNamesWithin()`.
     *
     * @param  list<string>  $keys
     * @return array<string, string|null>
     */
    public static function reach(array $keys): array
    {
        return self::isHierarchyEnabled() ? self::links($keys) : \array_fill_keys($keys, null);
    }

    /**
     * Return the names of every permission the held roles hold, with their
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
    public static function permissionNamesWithin(array $reach, array $held): ?array
    {
        $visible   = self::load(\array_keys($reach));
        $hierarchy = self::isHierarchyEnabled();
        $keys      = [];

        foreach ($visible as $role) {
            if ($hierarchy && $role->parent_id !== null && !\array_key_exists($role->parent_id, $reach)) {
                return null;
            }
        }

        foreach (\array_intersect($held, \array_keys($visible)) as $role) {
            $keys[] = $role;

            foreach ($hierarchy ? self::chain($visible[$role], $visible) : [] as $ancestor) {
                $keys[] = $ancestor->id;
            }
        }

        return self::permissionNames($keys);
    }

    /**
     * Return the names of the permissions attached to the roles with the given
     * keys, in one query through the permission model.
     *
     * @param  list<string>  $roleKeys
     * @return list<string>
     */
    private static function permissionNames(array $roleKeys): array
    {
        if ($roleKeys === []) {
            return [];
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $class */
        $class = config('authorization.models.permission', Permission::class);

        /** @var string $pivot */
        $pivot = config('authorization.tables.role_permissions', 'role_permissions');
        $model = new $class;

        /** @var list<string> */
        return $class::query()
            ->useWritePdo()
            ->join($pivot, $pivot . '.permission_id', '=', $model->getQualifiedKeyName())
            ->whereIn($pivot . '.role_id', $roleKeys)
            ->distinct()
            ->pluck($model->qualifyColumn('name'))
            ->all();
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
