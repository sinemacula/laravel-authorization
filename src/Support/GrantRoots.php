<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Administration\DependencyPins;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\GrantApplications;
use SineMacula\Laravel\Authorization\Database\LiveGrants;
use SineMacula\Laravel\Authorization\Enums\GrantScopeStatus;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;

/**
 * The roots of a set of grantees' live grants, in every tenant and every
 * application, read in one query over the grant tables (AUTHZ-14.2,
 * AUTHZ-13.8).
 *
 * A grant is a live row of a role granted, a permission granted directly or a
 * policy attached, a policy that only denies included (N82); roles are not
 * expanded into their permissions, since a role's root is where it was granted.
 * A row that has expired, as `LiveGrants` reads it, is no grant, and neither is
 * an attachment of an inline policy to a grantee it does not belong to, which
 * no check applies (see `InlinePolicies`). Boundaries and guardrails are
 * constraints on grants, not grants, and are never read. A grant's root is the
 * tenant its row names, or the platform for a row naming none.
 *
 * The grantees are matched by their exact morph type and key, so two grantees
 * sharing a key under different types are never confused. Every read is on the
 * write connection (AUTHZ-12.4), and is one query, whatever the number of
 * grantees, grants or tenants, and however deep the tree: the tenant's subtree
 * is nested whole as the tree's query, never loaded.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GrantRoots
{
    /** @var string The alias the tenant tree's subtree query is nested under. */
    private const string SUBTREE = 'grant_root_subtree';

    /** @var string The alias the grant tables' rows are read under. */
    private const string ROOTS = 'grant_roots';

    /** @var string The column of a grant row, and of a subtree row, naming its tenant's type. */
    private const string TENANT_TYPE = 'tenant_type';

    /** @var string The column of a grant row, and of a subtree row, naming its tenant's key. */
    private const string TENANT_ID = 'tenant_id';

    /** @var array<string, \SineMacula\Laravel\Authorization\Support\Reference> The grantees, each once, by their type and key. */
    private array $grantees;

    /**
     * Create a new reader of the grantees' grant roots.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $grantees
     */
    public function __construct(array $grantees)
    {
        $unique = [];

        foreach ($grantees as $grantee) {
            $unique[\serialize([$grantee->type, $grantee->id])] = $grantee;
        }

        $this->grantees = $unique;
    }

    /**
     * Return the condition a grant row meets when its root is the tenant or
     * below it in the tree: the tenant's own pair for a flat tree, else the
     * tree's subtree query nested whole. The subtree must be a query on the
     * package's connection, since it runs inside the grant query; it is
     * compiled each time it is nested, never changed, so the one query serves
     * every grant table.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Contracts\TenantTree  $tree
     * @return \Closure(\Illuminate\Database\Query\Builder, string): void
     *
     * @throws \UnexpectedValueException
     */
    public static function within(Reference $tenant, TenantTree $tree): \Closure
    {
        if ($tree instanceof FlatTenantTree) {
            return static function (Builder $row, string $table) use ($tenant): void {
                $row->where($table . '.' . self::TENANT_TYPE, $tenant->type)->where($table . '.' . self::TENANT_ID, $tenant->id);
            };
        }

        $subtree = self::subtreeOf($tree->subtree($tenant));

        return static function (Builder $row, string $table) use ($subtree): void {
            $row->whereExists(static function (Builder $exists) use ($subtree, $table): void {
                $exists->selectRaw('1')
                    ->fromSub($subtree, self::SUBTREE)
                    ->whereColumn(self::SUBTREE . '.' . self::TENANT_TYPE, $table . '.' . self::TENANT_TYPE)
                    ->whereColumn(self::SUBTREE . '.' . self::TENANT_ID, $table . '.' . self::TENANT_ID);
            });
        };
    }

    /**
     * Classify the roots against a tenant: outside when any is the platform, or
     * names a tenant the condition does not hold within; unknown when none is
     * outside but a row names half a tenant, one tenant column without the
     * other, and cannot be read; within otherwise, as with no grants at all.
     *
     * Without the condition, for a tree that cannot be read, only a root at the
     * platform is outside, and every other root is taken as within: the caller
     * cannot answer within then.
     *
     * @param  (\Closure(\Illuminate\Database\Query\Builder, string): void)|null  $within
     * @return \SineMacula\Laravel\Authorization\Enums\GrantScopeStatus
     */
    public function against(?\Closure $within): GrantScopeStatus
    {
        if ($this->grantees === []) {
            return GrantScopeStatus::WITHIN;
        }

        $found = $this->read(static function (Builder $query, string $table) use ($within): void {
            $query->where(static function (Builder $root) use ($table, $within): void {
                $root->whereNull($table . '.' . self::TENANT_TYPE)->orWhereNull($table . '.' . self::TENANT_ID);

                if ($within === null) {
                    return;
                }

                $root->orWhereNot(static fn (Builder $row) => $within($row, $table));
            });
        })->distinct()->pluck('is_unreadable')->map(static fn (mixed $flag): bool => \in_array($flag, [1, '1'], true))->all();

        return match (true) {
            \in_array(false, $found, true) => GrantScopeStatus::OUTSIDE,
            $found !== []                  => GrantScopeStatus::UNKNOWN,
            default                        => GrantScopeStatus::WITHIN,
        };
    }

    /**
     * Determine whether any grant applies in the chain's tenant, as a check
     * there reads it (see `TenantChain::grants()`): a platform-wide grant, one
     * made in the tenant, or one made in an ancestor that reaches below it.
     * Given an application, only the grants that hold in it count (see
     * `GrantApplications`); without one, a grant counts in whichever
     * application it holds.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\TenantChain  $chain
     * @param  string|null  $application
     * @return bool
     */
    public function appliesIn(TenantChain $chain, ?string $application = null): bool
    {
        if ($this->grantees === []) {
            return false;
        }

        return $this->read(static function (Builder $query, string $table) use ($chain, $application): void {
            $chain->grants($query, $table);

            if ($application === null) {
                return;
            }

            GrantApplications::only($query, $table, $application);
        })->exists();
    }

    /**
     * Determine whether any grant applies in the chain's tenant, as
     * `appliesIn()` does in every application, reading each grant table on its
     * own, the role grants, then the permission grants, then the policy
     * attachments, at most one row of each, under a lock (see
     * `Administration\DependencyPins::lockCoverage()`), and stopping at the
     * first that holds one. A locking read sees the latest committed rows,
     * whatever snapshot the transaction reads otherwise, and the row it finds
     * cannot be revoked until the transaction ends; it is never a union, which
     * PostgreSQL cannot lock.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\TenantChain  $chain
     * @return bool
     *
     * @throws \LogicException
     */
    public function appliesUnderLock(TenantChain $chain): bool
    {
        if ($this->grantees === []) {
            return false;
        }

        $connection = AuthorizationConnection::connection();

        foreach (GrantTarget::cases() as $target) {
            $rows = $this->rowsOf($connection, $target, static function (Builder $query, string $table) use ($chain): void {
                $chain->grants($query, $table);
            });

            if (DependencyPins::lockCoverage($rows->limit(1)) !== []) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the query of the grantees' live grant rows that meet the
     * condition, from every grant table, each marked by whether it names half a
     * tenant, on the write connection.
     *
     * @param  \Closure(\Illuminate\Database\Query\Builder, string): void  $constrain
     * @return \Illuminate\Database\Query\Builder
     */
    private function read(\Closure $constrain): Builder
    {
        $connection = AuthorizationConnection::connection();
        $union      = null;

        foreach (GrantTarget::cases() as $target) {
            $rows  = $this->rowsOf($connection, $target, $constrain);
            $union = $union === null ? $rows : $union->unionAll($rows);
        }

        return $connection->query()->fromSub($union, self::ROOTS)->useWritePdo();
    }

    /**
     * Return the query of the grantees' live rows of one grant table that meet
     * the condition, leaving out an inline policy attached to a grantee it does
     * not belong to.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $target
     * @param  \Closure(\Illuminate\Database\Query\Builder, string): void  $constrain
     * @return \Illuminate\Database\Query\Builder
     */
    private function rowsOf(Connection $connection, GrantTarget $target, \Closure $constrain): Builder
    {
        $table   = $target->table();
        $grammar = $connection->getQueryGrammar();
        $type    = $grammar->wrap($table . '.' . self::TENANT_TYPE);
        $id      = $grammar->wrap($table . '.' . self::TENANT_ID);

        $query = $connection->query()
            ->from($table)
            ->selectRaw("case when {$type} is null and {$id} is null then 0 when {$type} is null or {$id} is null then 1 else 0 end as is_unreadable");

        $query->where(function (Builder $grantees) use ($table): void {
            foreach ($this->grantees as $grantee) {
                $grantees->orWhere(static function (Builder $pair) use ($table, $grantee): void {
                    $pair->where($table . '.authorizable_type', $grantee->type)->where($table . '.authorizable_id', $grantee->id);
                });
            }
        });

        LiveGrants::only($query, $table);

        if ($target === GrantTarget::POLICY) {
            InlinePolicies::attachedToTheirGrantee($query, $table);
        }

        $constrain($query, $table);

        return $query;
    }

    /**
     * Return the tree's subtree query as a query of the package's connection,
     * refusing anything else, since it is nested in the grant query.
     *
     * @param  mixed  $subtree
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \UnexpectedValueException
     */
    private static function subtreeOf(mixed $subtree): Builder
    {
        $query = $subtree instanceof EloquentBuilder ? $subtree->toBase() : $subtree;

        $connection = $query instanceof Builder ? $query->getConnection() : null;

        if (!$query instanceof Builder || !$connection instanceof Connection || $connection->getName() !== AuthorizationConnection::connection()->getName()) {
            throw new \UnexpectedValueException('The tenant tree\'s subtree is not a query on the package\'s connection.');
        }

        return $query;
    }
}
