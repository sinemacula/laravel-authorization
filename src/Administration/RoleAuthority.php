<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\LiveGrants;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\RoleGraph;

/**
 * The whole active authority a role hands out (AUTHZ-3.3, AUTHZ-7.2): the
 * permissions it carries live and the policies attached to it live, each with
 * its ancestors' when the hierarchy is enabled, so a delegated role grant, or a
 * new parent, is judged on everything a holder would get (see
 * `DefinitionConstraints` and `OperationConstraints`).
 *
 * It is read in a fixed number of queries, however many roles, permissions and
 * policies there are: one recursive query for the chain of every role above the
 * roles given, outside every tenant scope (see `RoleGraph::reach()`), one for
 * the permissions every role of the chain carries, one for the policies
 * attached to them and one to read those policies as stored. Every row is read
 * on the write connection outside every tenant scope, so an ancestor or a
 * permission another tenant owns still counts, whichever tenant the check is
 * decided in, and the authority read is never less than what a holder gets. A
 * chain that cannot be read whole, a role or a parent missing from it, or one
 * that returns to a role it has passed, reads as no authority at all, so a
 * change it would justify is never proved.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RoleAuthority
{
    /**
     * Create the authority of a chain of roles.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Models\Permission>  $permissions
     * @param  list<\SineMacula\Laravel\Authorization\Models\Policy>  $policies
     */
    private function __construct(

        /** The permissions the roles and their ancestors carry live. */
        public array $permissions,

        /** The policies attached live to the roles and their ancestors, as stored. */
        public array $policies,
    ) {}

    /**
     * Return the authority the roles with the keys hand out, with their
     * ancestors', or null when a chain cannot be read whole.
     *
     * @param  list<string>  $keys
     * @return self|null
     */
    public static function of(array $keys): ?self
    {
        $chain = self::chainsOf($keys);

        return $chain === null ? null : new self(self::permissionsOf($chain), self::policiesOf($chain));
    }

    /**
     * Return why handing out this authority across the change's reach and
     * lifetime is refused: the first refusal of the permission route for a
     * permission (see `Possession`), or of the policy route for a policy (see
     * `PolicyRoute`); or null when every one passes. A role's denies never
     * justify its allows: each policy's allows are weighed alone.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    public function refusal(OperationResource $operation, OperationChange $change, FurtherChecks $checks): ?DecisionReason
    {
        $refusal = null;

        foreach ($this->permissions as $permission) {
            $refusal ??= Possession::refusal($operation, $change, $permission, $checks);
        }

        foreach ($this->policies as $policy) {
            $refusal ??= PolicyRoute::refusal($operation, $change, $policy, $checks);
        }

        return $refusal;
    }

    /**
     * Return the keys of the roles with the keys given and of every role above
     * them, read outside every tenant scope, or null when a chain cannot be
     * read whole.
     *
     * @param  list<string>  $keys
     * @return list<string>|null
     */
    public static function chainsOf(array $keys): ?array
    {
        $links = RoleGraph::reach($keys);
        $chain = [];

        foreach ($keys as $key) {
            $walked = self::chainOf($key, $links);

            if ($walked === null) {
                return null;
            }

            $chain = [...$chain, ...$walked];
        }

        return \array_values(\array_unique($chain));
    }

    /**
     * Return the keys of the role and of each role above it, walking the links
     * from the role up to the root, or null when the walk reaches a role the
     * links do not hold, or one it has passed already.
     *
     * @param  string  $key
     * @param  array<string, string|null>  $links
     * @return list<string>|null
     */
    public static function chainOf(string $key, array $links): ?array
    {
        $chain   = [];
        $current = $key;

        while ($current !== null) {
            if (!\array_key_exists($current, $links) || \in_array($current, $chain, true)) {
                return null;
            }

            $chain[] = $current;
            $current = $links[$current];
        }

        return $chain;
    }

    /**
     * Return the permissions the roles of the chain carry live, each once, in
     * one query.
     *
     * @param  list<string>  $chain
     * @return list<\SineMacula\Laravel\Authorization\Models\Permission>
     */
    private static function permissionsOf(array $chain): array
    {
        if ($chain === []) {
            return [];
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $class */
        $class = config('authorization.models.permission', Permission::class);

        /** @var string $pivot */
        $pivot = config('authorization.tables.role_permissions', 'role_permissions');
        $model = new $class;
        $query = $class::query()->withoutGlobalScopes()->useWritePdo()
            ->join($pivot, $pivot . '.permission_id', '=', $model->getQualifiedKeyName())
            ->whereIn($pivot . '.role_id', $chain)
            ->select($model->qualifyColumn('*'))
            ->distinct();

        /** @var list<\SineMacula\Laravel\Authorization\Models\Permission> */
        return LiveGrants::only($query, $pivot)->get()->all();
    }

    /**
     * Return the policies attached live to the roles of the chain, in any
     * scope, as stored, in two queries.
     *
     * @param  list<string>  $chain
     * @return list<\SineMacula\Laravel\Authorization\Models\Policy>
     */
    private static function policiesOf(array $chain): array
    {
        if ($chain === []) {
            return [];
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $roles */
        $roles = config('authorization.models.role', Role::class);

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        /** @var string $table */
        $table = config('authorization.tables.authorizable_policies', 'authorizable_policies');
        $query = AuthorizationConnection::connection()->table($table)->useWritePdo()
            ->where($table . '.authorizable_type', (new $roles)->getMorphClass())
            ->whereIn($table . '.authorizable_id', $chain);

        $keys = LiveGrants::only($query, $table)->distinct()->pluck($table . '.policy_id')->all();

        if ($keys === []) {
            return [];
        }

        /** @var list<\SineMacula\Laravel\Authorization\Models\Policy> */
        return $class::query()->withoutGlobalScopes()->useWritePdo()->whereKey($keys)->get()->all();
    }
}
