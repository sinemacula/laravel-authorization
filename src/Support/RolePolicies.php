<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
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
 * to a role in one tenant applies only where the role is held there too. An
 * attachment naming half a tenant, and any attachment of a policy naming half a
 * tenant, counts for its denies alone wherever the role is held (see
 * `TenantColumns::attachments()`).
 *
 * The resolution first asks, in the query that reads the identity's own
 * attachments, whether any role holds a policy in the current scope, having
 * pinned the version every role's policy attachments share; only then are the
 * roles read. The roles are pinned before their hierarchy is read again, so a
 * hierarchy that moves while the resolution runs is seen, and the resolution is
 * returned but marked unstable.
 *
 * @phpstan-import-type RoleGrants from \SineMacula\Laravel\Authorization\Resolvers\GrantResolver
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RolePolicies
{
    /**
     * Return the relation onto the roles a grantee holds, whose policies it
     * also gets, or null for a grantee that holds no roles, such as a role, or
     * whose `roles()` is not the morph the role grants use.
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @formatter:off
     *
     * @param  object  $grantee
     * @return \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Role, \Illuminate\Database\Eloquent\Model>|null
     *
     * @formatter:on
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     */
    public static function heldBy(object $grantee): ?MorphToMany
    {
        /** @var mixed $roles */
        $roles = $grantee instanceof SupportsRoles && \method_exists($grantee, 'roles') ? $grantee->roles() : null;

        /** @var \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Role, \Illuminate\Database\Eloquent\Model>|null */
        return $roles instanceof MorphToMany ? $roles : null;
    }

    /**
     * Return a query for at most one attachment of a policy to any role that
     * holds in the current tenant and application and has not expired, with the
     * given columns, so a resolution can tell whether any role's policy can
     * apply.
     *
     * @param  RoleGrants  $roles
     * @param  list<string>  $columns
     * @return \Illuminate\Database\Query\Builder
     */
    public static function probe(MorphToMany $roles, array $columns): Builder
    {
        $table = self::table();

        return self::scoped($table)
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
     * A resolution tracking grant usage (see `ResolutionPins::isRouting()`)
     * reads, in the same queries, the chain of each role held and the role each
     * attachment is to, so it can say which route each policy came through.
     *
     * @param  \Illuminate\Database\Eloquent\Collection<int, covariant \Illuminate\Database\Eloquent\Model>  $held
     * @param  RoleGrants  $roles
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionPins  $pins
     * @return \SineMacula\Laravel\Authorization\Support\InheritedPolicies
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function heldThrough(EloquentCollection $held, MorphToMany $roles, ResolutionPins $pins): InheritedPolicies
    {
        // With no role held, every read below returns at once, without a query.
        /** @var list<string> $keys */
        $keys    = \array_keys($held->getDictionary());
        $reach   = RoleGraph::reach($keys);
        $columns = ['policy_id', 'expires_at', 'tenant_type', 'tenant_id'];

        $pins->roles(\array_keys($reach));

        $chains = $pins->isRouting() ? RoleGraph::chainsWithin($reach, $keys) : null;
        $within = match (true) {
            !$pins->isRouting() => RoleGraph::keysWithin($reach, $keys),
            $chains === null    => null,
            default             => RoleGraph::keysOf($chains),
        };
        $type   = $roles->getRelated()->getMorphClass();
        $rows   = self::attachments($type, $within ?? self::afresh($roles, $keys), $pins->isRouting() ? [...$columns, 'authorizable_id'] : $columns);
        $grants = $rows === [] ? [] : $held->map(static fn (Model $role): mixed => self::grantExpiry($role))->all();
        $placed = \array_values(\array_filter($rows, static fn (array $row): bool => !TenantColumns::isHalf($row['tenant_type'] ?? null, $row['tenant_id'] ?? null)));
        $found  = \array_values(\array_filter(\array_column($rows, 'policy_id'), \is_string(...)));

        return new InheritedPolicies(
            $found,
            GrantExpiry::nearest(GrantExpiry::nearest(null, \array_column($rows, 'expires_at')), $grants),
            $within !== null,
            $chains,
            $pins->isRouting() ? self::byRole($placed) : [],
            \array_values(\array_diff($found, \array_filter(\array_column($placed, 'policy_id'), \is_string(...)))),
        );
    }

    /**
     * Return the attachments of policies to the roles with the given keys that
     * hold in the current scope, each as the policy's key, the key of the role
     * it is attached to and whether it names a whole scope, so its allows count
     * too, in one query on the write connection, as `heldThrough()` reads them:
     * the attachments an explained check tells apart by the role that holds
     * them.
     *
     * @param  string  $type
     * @param  list<string>  $keys
     * @return list<array{policy_id: string, role_id: string, is_whole: bool}>
     */
    public static function attachedTo(string $type, array $keys): array
    {
        /** @var list<array{policy_id: string, authorizable_id: string, tenant_type: string|null, tenant_id: string|null}> $attached */
        $attached = self::attachments($type, $keys, ['policy_id', 'authorizable_id', 'tenant_type', 'tenant_id']);
        $rows     = [];

        foreach ($attached as $row) {
            $rows[] = ['policy_id' => $row['policy_id'], 'role_id' => $row['authorizable_id'], 'is_whole' => !TenantColumns::isHalf($row['tenant_type'], $row['tenant_id'])];
        }

        return $rows;
    }

    /**
     * Return the keys of the policies attached to each role, by the role's key,
     * from the attachments read.
     *
     * @param  list<array<string, mixed>>  $rows
     * @return array<string, list<string>>
     */
    private static function byRole(array $rows): array
    {
        $attached = [];

        foreach ($rows as $row) {
            $role   = $row['authorizable_id'] ?? null;
            $policy = $row['policy_id']       ?? null;

            if (!\is_scalar($role) || !\is_scalar($policy)) {
                continue;
            }

            $attached[(string) $role][] = (string) $policy;
        }

        return $attached;
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
     * @param  RoleGrants  $roles
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
     * hold in the current scope, in one query on the write connection, in no
     * particular order: the evaluator orders the policies, and a policy
     * attached to more than one of the roles is listed once by the resolution.
     *
     * @param  string  $type
     * @param  list<string>  $keys
     * @param  list<string>  $columns
     * @return list<array<string, mixed>>
     */
    private static function attachments(string $type, array $keys, array $columns = ['policy_id', 'expires_at']): array
    {
        if ($keys === []) {
            return [];
        }

        $table = self::table();

        /** @var list<array<string, mixed>> */
        return self::scoped($table)
            ->useWritePdo()
            ->where($table . '.authorizable_type', $type)
            ->whereIn($table . '.authorizable_id', $keys)
            ->get($columns)
            ->map(static fn (object $row): array => (array) $row)
            ->all();
    }

    /**
     * Query the attachments table for the rows that hold in the current tenant
     * and application and have not expired, as a grantee's relation reads them,
     * with those whose denies alone count in every scope (see
     * `TenantColumns::attachments()`), leaving out an attachment of an inline
     * policy to a role it does not belong to.
     *
     * @param  string  $table
     * @return \Illuminate\Database\Query\Builder
     */
    private static function scoped(string $table): Builder
    {
        $query = AuthorizationConnection::connection()->table($table)->where(static function (Builder $query) use ($table): void {
            TenantColumns::attachments(TenantScope::currentChain(), $query, $table);
            GrantApplications::only($query, $table, TenantScope::currentApplication());
        });

        return LiveGrants::only(InlinePolicies::attachedToTheirGrantee($query, $table), $table);
    }

    /**
     * Return the attachments table, as `authorization.tables` names it.
     *
     * @return string
     */
    private static function table(): string
    {
        return TableNames::get('authorizable_policies');
    }
}
