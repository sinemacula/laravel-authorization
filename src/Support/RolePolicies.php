<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Contracts\Database\Query\Builder as QueryBuilder;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\GrantApplications;
use SineMacula\Laravel\Authorization\Database\LiveGrants;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;

/**
 * Reads the policies an identity gets through its roles (AUTHZ-7.2).
 *
 * A policy attached to a role, through the `authorizable_policies` table with
 * the role as the grantee, applies to whoever holds the role, and to whoever
 * holds a role below it when the hierarchy is enabled, as the role's
 * permissions do: the roles are read through `RoleGraph`, the same reach the
 * permissions take. It applies only where both grants hold: the identity's
 * grant of the role and the role's attachment of the policy each hold in the
 * current tenant (and through a tenant above it only when that grant reaches
 * its subtree) and application, and neither has expired, so a policy attached
 * to a role in one tenant applies only where the role is held there too.
 *
 * The resolution first asks, in the query that reads the identity's own
 * attachments, whether any role holds a policy in the current scope, having
 * pinned the version every role's policy attachments share; only then are the
 * roles read. The roles are pinned before their hierarchy is read again, so a
 * hierarchy that moves while the resolution runs is seen, and the resolution is
 * returned but marked unstable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RolePolicies
{
    /**
     * Return a query for at most one attachment of a policy to any role that
     * holds in the current tenant and application and has not expired, with the
     * given columns, so a resolution can tell whether any role's policy can
     * apply.
     *
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Role, \Illuminate\Database\Eloquent\Model>  $roles
     * @param  list<string>  $columns
     * @return \Illuminate\Database\Query\Builder
     */
    public static function probe(MorphToMany $roles, array $columns): Builder
    {
        $table = self::table();

        return self::scoped(AuthorizationConnection::connection()->table($table), $table)
            ->where($table . '.authorizable_type', $roles->getRelated()->getMorphClass())
            ->select(\array_map(static fn (string $column): string => "{$table}.{$column}", $columns))
            ->limit(1);
    }

    /**
     * Return the policies attached to the held roles, and to the roles above
     * them when the hierarchy is enabled, within the current scope, pinning
     * every role reached before its hierarchy is read again.
     *
     * The nearest expiry counts the identity's grants of the roles as well as
     * the roles' attachments, since a policy stops applying when either lapses.
     *
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model>  $held
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Role, \Illuminate\Database\Eloquent\Model>  $roles
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionPins  $pins
     * @return \SineMacula\Laravel\Authorization\Support\InheritedPolicies
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function heldThrough(EloquentCollection $held, MorphToMany $roles, ResolutionPins $pins): InheritedPolicies
    {
        /** @var list<string> $keys */
        $keys = \array_map(\strval(...), \array_keys($held->getDictionary()));

        if ($keys === []) {
            return new InheritedPolicies;
        }

        $reach = RoleGraph::reach($keys);

        $pins->roles(\array_map(\strval(...), \array_keys($reach)));

        $within = RoleGraph::keysWithin($reach, $keys);
        $rows   = self::attachments($roles->getRelated()->getMorphClass(), $within ?? self::afresh($roles, $keys));
        $grants = $rows === [] ? [] : $held->map(static fn (Model $role): mixed => self::grantExpiry($role))->all();

        return new InheritedPolicies(
            \array_values(\array_unique(\array_column($rows, 'policy_id'))),
            GrantExpiry::nearest(GrantExpiry::nearest(null, \array_column($rows, 'expires_at')), $grants),
            $within !== null,
        );
    }

    /**
     * Return the expiry of the grant a held role was read through.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $role
     * @return mixed
     */
    private static function grantExpiry(Model $role): mixed
    {
        /** @var \Illuminate\Database\Eloquent\Model $pivot */
        $pivot = $role->getRelation('pivot');

        return $pivot->getAttribute('expires_at');
    }

    /**
     * Return the keys of the held roles and their ancestors, reading the roles
     * and their hierarchy afresh, for a resolution whose hierarchy moved while
     * it ran.
     *
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Role, \Illuminate\Database\Eloquent\Model>  $roles
     * @param  list<string>  $keys
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function afresh(MorphToMany $roles, array $keys): array
    {
        /** @var list<\SineMacula\Laravel\Authorization\Models\Role> $fresh */
        $fresh = $roles->getRelated()->newQuery()->useWritePdo()->whereKey($keys)->get()->all();

        return RoleGraph::keysHeldBy($fresh);
    }

    /**
     * Read the attachments of policies to the roles with the given keys that
     * hold in the current scope, in one query on the write connection, in order
     * of policy and role.
     *
     * @param  string  $type
     * @param  list<string>  $keys
     * @return list<array{policy_id: string, expires_at: string|null}>
     */
    private static function attachments(string $type, array $keys): array
    {
        if ($keys === []) {
            return [];
        }

        $table = self::table();

        /** @var list<array{policy_id: string, expires_at: string|null}> */
        return self::scoped(AuthorizationConnection::connection()->table($table), $table)
            ->useWritePdo()
            ->where($table . '.authorizable_type', $type)
            ->whereIn($table . '.authorizable_id', \array_values(\array_unique($keys)))
            ->orderBy($table . '.policy_id')
            ->orderBy($table . '.authorizable_id')
            ->get([$table . '.policy_id as policy_id', $table . '.expires_at as expires_at'])
            ->map(static fn (object $row): array => (array) $row)
            ->all();
    }

    /**
     * Limit a query of the attachments table to the rows that hold in the
     * current tenant and application and have not expired, as a grantee's
     * relation reads them.
     *
     * @template TQuery of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  TQuery  $query
     * @param  string  $table
     * @return TQuery
     */
    private static function scoped(QueryBuilder $query, string $table): QueryBuilder
    {
        $query->where(static function (QueryBuilder $query) use ($table): void {
            TenantScope::currentChain()->grants($query, $table);
            GrantApplications::only($query, $table, TenantScope::currentApplication());
        });

        return LiveGrants::only($query, $table);
    }

    /**
     * Return the attachments table, as `authorization.tables` names it.
     *
     * @return string
     */
    private static function table(): string
    {
        /** @var string */
        return config('authorization.tables.authorizable_policies', 'authorizable_policies');
    }
}
