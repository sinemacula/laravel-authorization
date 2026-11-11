<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use SineMacula\Laravel\Authorization\Config\SwitchConfigValidator;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\RoleGraph;

/**
 * The role hierarchy as an access review reads it, in a fixed number of queries
 * however many roles there are and however deep the hierarchy runs: a role's
 * holder holds what the role and every role above it carry, when the hierarchy
 * is enabled (AUTHZ-3.4), so the holders of a role are found through the grants
 * of every role below it, and what a role's holder holds through every role
 * above it.
 *
 * A chain runs from a role up through its parents, as `RoleGraph` walks it for
 * a check: it ends at a role that is missing, or that the reviewed tenant does
 * not see in a review of what applies there (see `ReviewRun::sees()`), and a
 * role the tenant does not see holds nothing there itself. A role naming half a
 * tenant, a type without a key or a key without a type, which the package never
 * writes, is seen in no review of what applies, at the platform or in a tenant,
 * as the tenant scope shows it nowhere (see `TenantChain::whereNullTenant()`).
 * A chain that returns to a role it has passed refuses the review with
 * `RoleHierarchyCycleException`, as a check refuses; the role service never
 * writes one. With the hierarchy disabled a chain is its role alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RoleChains
{
    /** @var string The name the recursive query gives the roles it walks down to. */
    private const string BELOW = 'authorization_review_roles_below';

    /**
     * Return the roles at or below the carriers whose chain reaches one of
     * them, each by its key with its chain, from the role up, as far as it goes
     * among those roles: one recursive query for the roles below, one read of
     * them.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  list<string>  $carriers
     * @return array<string, list<string>>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function below(ReviewRun $run, array $carriers): array
    {
        $roles  = self::visible($run, self::isHierarchyEnabled() ? self::descendants($carriers) : $carriers);
        $chains = [];

        foreach (\array_map(strval(...), \array_keys($roles)) as $key) {
            $chain = self::chain($key, $roles);

            if (\array_intersect($chain, $carriers) === []) {
                continue;
            }

            $chains[$key] = $chain;
        }

        return $chains;
    }

    /**
     * Return the chain of each held role the reviewed tenant sees, from the
     * role up, by the role's key: one recursive query for the roles above, one
     * read of them.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  list<string>  $held
     * @return array<string, list<string>>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function above(ReviewRun $run, array $held): array
    {
        $roles  = self::visible($run, \array_map(strval(...), \array_keys(RoleGraph::reach($held))));
        $chains = [];

        foreach (\array_intersect($held, \array_map(strval(...), \array_keys($roles))) as $key) {
            $chains[$key] = self::chain($key, $roles);
        }

        return $chains;
    }

    /**
     * Return the references to the roles of a chain, in its order.
     *
     * @param  list<string>  $chain
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    public static function path(array $chain): array
    {
        $type = Definitions::morph(GrantTarget::ROLE);

        return \array_map(static fn (string $key): Reference => new Reference($type, $key), $chain);
    }

    /**
     * Return the chain from the role up through the roles given, its parent
     * when the hierarchy is enabled and the parent is among them, then its
     * parent's, and so on.
     *
     * @param  string  $key
     * @param  array<string, array{parent: string|null, name: string}>  $roles
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function chain(string $key, array $roles): array
    {
        $chain     = [$key];
        $passed    = [$key => true];
        $current   = $key;
        $hierarchy = self::isHierarchyEnabled();

        while ($hierarchy && ($parent = $roles[$current]['parent'] ?? null) !== null && isset($roles[$parent])) {
            if (isset($passed[$parent])) {
                throw new RoleHierarchyCycleException(roleName: $roles[$key]['name'], proposedParentName: $roles[$parent]['name']);
            }

            $passed[$parent] = true;
            $chain[]         = $parent;
            $current         = $parent;
        }

        return $chain;
    }

    /**
     * Read the roles with the keys, keeping those the reviewed tenant sees,
     * never one naming half a tenant in a review of what applies, each by its
     * key with its parent's key and its name, in one query on the write
     * connection, outside every tenant scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  list<string>  $keys
     * @return array<string, array{parent: string|null, name: string}>
     */
    private static function visible(ReviewRun $run, array $keys): array
    {
        if ($keys === []) {
            return [];
        }

        [$table, $key] = Definitions::tableOf(GrantTarget::ROLE);

        $rows = AuthorizationConnection::connection()
            ->table($table)
            ->useWritePdo()
            ->whereIn($key, $keys)
            ->get([$key . ' as role_key', 'parent_id', 'name', 'tenant_type', 'tenant_id']);

        $roles = [];

        foreach ($rows as $row) {
            /** @var array{role_key: int|string, parent_id: int|string|null, name: string, tenant_type: string|null, tenant_id: int|string|null} $columns */
            $columns     = (array) $row;
            [$type, $id] = [$columns['tenant_type'], $columns['tenant_id']];
            $owner       = $type === null || $id === null ? null : new Reference($type, (string) $id);
            $isHidden    = ($type === null) !== ($id === null) ? $run->isApplicability() : !$run->sees($owner);

            if ($isHidden) {
                continue;
            }

            $roles[(string) $columns['role_key']] = ['parent' => $columns['parent_id'] === null ? null : (string) $columns['parent_id'], 'name' => $columns['name']];
        }

        return $roles;
    }

    /**
     * Return the keys of the roles and of every role below them, each once, in
     * one recursive query on the write connection that ignores the tenant
     * scope. `union` rather than `union all` drops a row already produced, so a
     * cycle in the stored hierarchy ends the recursion.
     *
     * @param  list<string>  $keys
     * @return list<string>
     */
    private static function descendants(array $keys): array
    {
        if ($keys === []) {
            return [];
        }

        [$table, $key] = Definitions::tableOf(GrantTarget::ROLE);

        $connection = AuthorizationConnection::connection();
        $grammar    = $connection->getQueryGrammar();
        $wrapped    = $grammar->wrapTable($table);
        $column     = $grammar->wrap($key);
        $parent     = $grammar->wrap('parent_id');
        $below      = $grammar->wrap(self::BELOW);
        $marks      = \implode(', ', \array_fill(0, \count($keys), '?'));

        $rows = $connection->selectFromWriteConnection(
            "with recursive {$below} ({$column}) as ("
                . "select {$column} from {$wrapped} where {$column} in ({$marks})"
                . " union select {$wrapped}.{$column} from {$wrapped}"
                . " inner join {$below} on {$wrapped}.{$parent} = {$below}.{$column}"
                . ") select {$column} from {$below}",
            $keys,
        );

        return \array_map(strval(...), \array_column($rows, $key));
    }

    /**
     * Determine whether the role hierarchy is enabled.
     *
     * @return bool
     */
    private static function isHierarchyEnabled(): bool
    {
        return SwitchConfigValidator::isEnabled('hierarchy');
    }
}
