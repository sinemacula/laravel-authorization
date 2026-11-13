<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exclusions\Support;

use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Config\SwitchConfigValidator;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableMachine;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\BreakGlassActivations;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Reviews\Support\Definitions;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRow;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRows;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun;
use SineMacula\Laravel\Authorization\Reviews\Support\RoleChains;
use SineMacula\Laravel\Authorization\Reviews\Support\TenantRelations;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Who holds each of a set of roles, and through which grants (AUTHZ-11.8,
 * N135), as the conflict report reads them: every live grant, in every tenant
 * and application, of the role or of a role below it, which inherits it while
 * the role hierarchy is enabled, each one route. A live break-glass activation
 * is read as the grant it stands for (see `BreakGlassActivations`): one naming
 * a machine counts for nothing, and one held by an identity never reaches its
 * principals (see `of()`).
 *
 * A grant holds the roles of its chain, from the role granted up through its
 * parents, as a check walks it (see `RoleGraph`) in a tenant the grant holds
 * in: a check in a tenant sees the platform's roles and those of the tenant and
 * its ancestors, so a role owned by a tenant is held where the grant and the
 * owner's subtree hold together, as a policy attachment's scope meets a grant
 * (see `TenantRelations::canHoldTogether()`). Each role of the chain narrows
 * where it is held to the subtree of its owner when that lies below where the
 * chain was held so far, so a grant at the platform holds a tenant's role in
 * the tenant's subtree, and a grant reaching below its tenant holds a role
 * owned below it there. The chain ends at a role that is missing, that names
 * half a tenant, or that no check holding the roles before it sees, so a tenant
 * moved under another parent stops holding what a role of its old parent's
 * carries. A grant naming half a tenant holds nothing anywhere (N130).
 *
 * It reads in a fixed number of queries, never one for each holder or tenant:
 * the roles below the set in one recursive query (`RoleChains`), then one read
 * of them and of every role whose parent is among them, repeated only for a
 * role it finds that the first query did not; the grants and the activations of
 * all of them together, as `GrantRows` selects them, a chunk of the roles at a
 * time, live at one instant (see `ReviewRun`); and whether each grant's tenant
 * and the owners of its chain lie within one another, settled together (see
 * `TenantRelations::settleWithin()`). Every read is on the write connection,
 * outside every tenant scope. Read locked, the roles, grants and activations
 * are read under shared locks, so they are the rows as last committed whatever
 * snapshot the transaction reads, as MySQL's repeatable read would otherwise
 * keep it, and they stay so until it ends.
 *
 * Given a write (see `ExclusionWrite`), the holdings are read as it would leave
 * them: a role it re-parents is read with the roles below it and the parent it
 * would have, and an activation it proposes is read beside the stored ones.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExclusionHoldings
{
    /** @var list<string> The columns of a break-glass activation a route reads, each under a grant row's name. */
    private const array ACTIVATION_COLUMNS = [
        'role_id as target_id',
        'authorizable_type as grantee_type',
        'authorizable_id as grantee_id',
        'tenant_type',
        'tenant_id',
        'include_subtree',
        'application',
        'expires_at',
    ];

    /**
     * Create the holdings read.
     *
     * @param  array<string, array<string, list<\SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute>>>  $routes
     * @param  array<string, array<string, list<\SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute>>>  $activated
     * @param  array<string, \SineMacula\Laravel\Authorization\Support\Reference>  $grantees
     */
    private function __construct(

        /** The routes through grants to each role, by the role's key, then by the key of their grantee. */
        private array $routes,

        /** The routes through break-glass activations to each role, keyed as the routes through grants are. */
        private array $activated,

        /** Every grantee holding one of the roles, by its key. */
        private array $grantees,
    ) {}

    /**
     * Read who holds each of the roles, and through which grants, weighing
     * whether one tenant lies within another with the relations given.
     *
     * @param  list<string>  $roles
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\TenantRelations  $relations
     * @param  bool  $isLocked
     * @param  \SineMacula\Laravel\Authorization\Exclusions\Support\ExclusionWrite|null  $write
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     * @throws \UnexpectedValueException
     */
    public static function read(array $roles, TenantRelations $relations, bool $isLocked = false, ?ExclusionWrite $write = null): self
    {
        $parents = $write->parents ?? [];
        $family  = self::family([...$roles, ...\array_keys($parents)], $isLocked);

        foreach ($family as $key => $role) {
            $family[$key]['parent'] = $parents[$key] ?? $role['parent'];
        }

        [$granted, $activated] = self::grants(ReviewRun::of(ReviewScope::everywhere()), \array_keys($family), $isLocked);

        $activated = \array_filter([...$activated, ...$write->proposed ?? []], static fn (GrantRow $row): bool => !self::isMachine($row->grantee));
        $type      = Definitions::morph(GrantTarget::ROLE);
        $routes    = [[], []];
        $found     = [];

        $relations->settleWithin(self::questions([...$granted, ...$activated], $family));

        foreach ([$granted, $activated] as $source => $grants) {
            foreach ($grants as $grant) {
                foreach (self::reached($grant, $family, $relations, $roles, $type) as $role => $route) {
                    $routes[$source][$role][self::key($grant->grantee)][] = $route;
                    $found[self::key($grant->grantee)]                    = $grant->grantee;
                }
            }
        }

        return new self($routes[0], $routes[1], $found);
    }

    /**
     * Return the routes through which the grantee holds the role: through its
     * grants and its break-glass activations, or, weighed as another subject's
     * identity, which no activation reaches, through its grants alone.
     *
     * @param  string  $role
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  bool  $isIdentity
     * @return list<\SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute>
     */
    public function of(string $role, Reference $grantee, bool $isIdentity = false): array
    {
        $key = self::key($grantee);

        return [...$this->routes[$role][$key] ?? [], ...$isIdentity ? [] : $this->activated[$role][$key] ?? []];
    }

    /**
     * Return the grantees holding any of the roles given, each once, by key.
     *
     * @param  string  ...$roles
     * @return array<string, \SineMacula\Laravel\Authorization\Support\Reference>
     */
    public function holders(string ...$roles): array
    {
        $holders = [];

        foreach ($roles as $role) {
            foreach (\array_keys([...$this->routes[$role] ?? [], ...$this->activated[$role] ?? []]) as $key) {
                $holders[$key] = $this->grantees[$key];
            }
        }

        return $holders;
    }

    /**
     * Return the key a grantee is held under: its type and key, each exact.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return string
     */
    public static function key(Reference $grantee): string
    {
        return \serialize([$grantee->type, $grantee->id]);
    }

    /**
     * Determine whether the grantee is a machine, as its model class says (see
     * `AuthorizableMachine`).
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return bool
     */
    public static function isMachine(Reference $grantee): bool
    {
        $class = Relation::getMorphedModel($grantee->type) ?? $grantee->type;

        return \is_a($class, AuthorizableMachine::class, true);
    }

    /**
     * Return the route the grant gives to each of the roles its chain reaches,
     * by the role's key, with where a check sees it held: none for a grant
     * naming half a tenant, which holds nothing anywhere.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\GrantRow  $grant
     * @param  array<string, array{parent: string|null, name: string, owner: \SineMacula\Laravel\Authorization\Support\Reference|null, isHalf: bool}>  $family
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\TenantRelations  $relations
     * @param  list<string>  $roles
     * @param  string  $type
     * @return array<string, \SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function reached(GrantRow $grant, array $family, TenantRelations $relations, array $roles, string $type): array
    {
        $scope = $grant->isPlaced() ? $grant->scope : null;

        if ($scope === null) {
            return [];
        }

        $chain  = self::chain($grant->targetId, $family, $scope, $relations);
        $keys   = \array_map(strval(...), \array_keys($chain));
        $routes = [];

        foreach ($roles as $role) {
            $at = \array_search($role, $keys, true);

            if ($at === false) {
                continue;
            }

            /** @var non-empty-list<\SineMacula\Laravel\Authorization\Support\Reference> $path */
            $path = RoleChains::path(\array_slice($keys, 0, $at + 1));

            $routes[$role] = new ExclusionRoute($grant->grantee, new Reference($type, $role), $path, $scope, $chain[$role], $grant->expiresAt());
        }

        return $routes;
    }

    /**
     * Return the chain from the role up through its parents while the hierarchy
     * is enabled, each role by its key with where it is held, from the scope
     * given narrowed by each role (see `narrow()`), or, for no relations, with
     * the scope given, ending before a role that is missing or held nowhere,
     * refusing one that returns to a role it passed.
     *
     * @param  string  $key
     * @param  array<string, array{parent: string|null, name: string, owner: \SineMacula\Laravel\Authorization\Support\Reference|null, isHalf: bool}>  $family
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\TenantRelations|null  $relations
     * @return array<string, \SineMacula\Laravel\Authorization\Support\GrantScope>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function chain(string $key, array $family, GrantScope $scope, ?TenantRelations $relations): array
    {
        $chain     = [];
        $current   = $key;
        $hierarchy = SwitchConfigValidator::isEnabled('hierarchy');

        while ($current !== null && isset($family[$current])) {
            $held = $relations === null ? $scope : self::narrow($scope, $family[$current], $relations);

            if ($held === null) {
                break;
            }

            if (isset($chain[$current])) {
                throw new RoleHierarchyCycleException(roleName: $family[$key]['name'], proposedParentName: $family[$current]['name']);
            }

            $chain[$current] = $held;
            $scope           = $held;
            $current         = $hierarchy ? $family[$current]['parent'] : null;
        }

        return $chain;
    }

    /**
     * Return the pairs of tenants whether the grants' chains are held turns on:
     * each owner of a role of a chain against the grant's tenant and the owners
     * of the roles before it, each way round.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>  $grants
     * @param  array<string, array{parent: string|null, name: string, owner: \SineMacula\Laravel\Authorization\Support\Reference|null, isHalf: bool}>  $family
     * @return list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference}>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function questions(array $grants, array $family): array
    {
        $questions = [];

        foreach ($grants as $grant) {
            $chain   = self::chain($grant->targetId, $family, GrantScope::platform(), null);
            $owners  = \array_map(static fn (int|string $role): ?Reference => $family[$role]['owner'], \array_keys($chain));
            $tenants = [];

            foreach (\array_filter([$grant->scope?->tenant, ...$owners]) as $owner) {
                foreach ($tenants as $before) {
                    \array_push($questions, [$before, $owner], [$owner, $before]);
                }

                $tenants[] = $owner;
            }
        }

        return $questions;
    }

    /**
     * Return where a check sees the role held through a grant held so far in
     * the scope: anywhere the scope holds for a platform role; for a role a
     * tenant owns, where the scope and the owner's subtree hold together, the
     * subtree when it lies below the scope's tenant; and nowhere for a role
     * naming half a tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  array{parent: string|null, name: string, owner: \SineMacula\Laravel\Authorization\Support\Reference|null, isHalf: bool}  $role
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\TenantRelations  $relations
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope|null
     */
    private static function narrow(GrantScope $scope, array $role, TenantRelations $relations): ?GrantScope
    {
        $owner = $role['owner'];

        if ($owner === null) {
            return $role['isHalf'] ? null : $scope;
        }

        $owned = new GrantScope($owner, $scope->application);

        if (!$relations->canHoldTogether($scope, $owned)) {
            return null;
        }

        return $scope->tenant !== null && $relations->isWithin($scope->tenant, $owner) ? $scope : $owned;
    }

    /**
     * Return the roles at or below the roles given, each by its key with its
     * parent's key, its name and its owner, as last read: the roles below in
     * one recursive query, then a read of them and of every role whose parent
     * is among them, repeated for each role found that was not read yet.
     *
     * @param  list<string>  $roles
     * @param  bool  $isLocked
     * @return array<string, array{parent: string|null, name: string, owner: \SineMacula\Laravel\Authorization\Support\Reference|null, isHalf: bool}>
     */
    private static function family(array $roles, bool $isLocked): array
    {
        $hierarchy = SwitchConfigValidator::isEnabled('hierarchy');
        $pending   = $hierarchy ? RoleChains::descendants($roles) : $roles;
        $read      = [];
        $family    = [];

        while ($pending !== []) {
            $read    = [...$read, ...$pending];
            $family  = self::rolesOf($pending, $hierarchy, $isLocked) + $family;
            $pending = \array_values(\array_diff(\array_map(strval(...), \array_keys($family)), $read));
        }

        return $family;
    }

    /**
     * Read the roles with the keys and, with the hierarchy enabled, every role
     * whose parent is one of them, under a shared lock when asked.
     *
     * @param  list<string>  $keys
     * @param  bool  $hierarchy
     * @param  bool  $isLocked
     * @return array<string, array{parent: string|null, name: string, owner: \SineMacula\Laravel\Authorization\Support\Reference|null, isHalf: bool}>
     */
    private static function rolesOf(array $keys, bool $hierarchy, bool $isLocked): array
    {
        [$table, $key] = Definitions::tableOf(GrantTarget::ROLE);

        $query = AuthorizationConnection::connection()->table($table)->useWritePdo()->whereIn($key, $keys);

        if ($hierarchy) {
            $query->orWhereIn('parent_id', $keys);
        }

        if ($isLocked) {
            $query->sharedLock();
        }

        $roles = [];

        foreach ($query->get([$key . ' as role_key', 'parent_id', 'name', 'tenant_type', 'tenant_id']) as $row) {
            /** @var array{role_key: int|string, parent_id: int|string|null, name: string, tenant_type: string|null, tenant_id: int|string|null} $columns */
            $columns     = (array) $row;
            [$type, $id] = [$columns['tenant_type'], $columns['tenant_id']];

            $roles[(string) $columns['role_key']] = [
                'parent' => $columns['parent_id'] === null ? null : (string) $columns['parent_id'],
                'name'   => $columns['name'],
                'owner'  => $type === null || $id === null ? null : new Reference($type, (string) $id),
                'isHalf' => ($type === null) !== ($id === null),
            ];
        }

        return $roles;
    }

    /**
     * Read the live grants of the roles, and the live break-glass activations
     * of them as the grants they stand for (see `BreakGlassActivations`), in
     * every tenant and application, a chunk of the roles at a time, under a
     * shared lock when asked.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  list<string>  $roles
     * @param  bool  $isLocked
     * @return array{0: list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>, 1: list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>}
     */
    private static function grants(ReviewRun $run, array $roles, bool $isLocked): array
    {
        $table       = GrantTarget::ROLE->table();
        $activations = TableNames::get('break_glass');
        $rows        = [[], []];

        foreach (\array_chunk($roles, GrantRows::CHUNK) as $chunk) {
            $queries = [
                $run->live(GrantRows::of(GrantTarget::ROLE), $table)->whereIn($table . '.' . GrantTarget::ROLE->column(), $chunk),
                BreakGlassActivations::live(AuthorizationConnection::connection()->table($activations), $activations, Carbon::instance($run->now))
                    ->useWritePdo()
                    ->select(self::ACTIVATION_COLUMNS)
                    ->whereIn('role_id', $chunk),
            ];

            foreach ($queries as $source => $query) {
                \array_push($rows[$source], ...GrantRows::all($isLocked ? $query->sharedLock() : $query, GrantTarget::ROLE->value));
            }
        }

        return $rows;
    }
}
