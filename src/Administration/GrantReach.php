<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Query\Builder as QueryBuilder;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * The tenants a delegated grant reaches, read once, so what applies anywhere in
 * the reach is read in one query a table, with the reach in the query: the
 * platform, the grant's tenant and its ancestors, and, for a grant reaching
 * below its tenant, every tenant below it, as the bound tree's subtree query
 * selects them, read once; a platform-wide grant reaches every tenant.
 *
 * The rank and possession rules read what the grantee or the actor holds, and
 * what could cap or deny the actor, across this reach (see `RankComparison` and
 * `PossessionLimits`). A tree that cannot be read, or a subtree query that is
 * no query, throws, so the reach is never guessed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GrantReach
{
    /**
     * Create a new grant reach.
     *
     * @param  array<array-key, array{string, list<string>}>|null  $tenants
     */
    private function __construct(

        /** The tenants reached, each type with its keys; null for every tenant. */
        private ?array $tenants,
    ) {}

    /**
     * Return the reach of a grant in the scope, reading the tenant's ancestors
     * and, for a grant reaching below it, the tenants below it from the bound
     * tree, once.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    public static function of(GrantScope $scope): self
    {
        $tenant = $scope->tenant;

        if ($tenant === null) {
            return new self(null);
        }

        $tree    = TenantChain::tree();
        $reached = [...TenantChain::of($tenant, $tree)->tenants, ...($scope->includeSubtree ? self::below($tenant, $tree) : [])];
        $tenants = [];

        foreach ($reached as $reference) {
            $type = $reference->type;

            $tenants[$type] = [$type, [...($tenants[$type][1] ?? []), $reference->id]];
        }

        return new self($tenants);
    }

    /**
     * Limit a query of the table to its rows held in a tenant of the reach, and
     * its platform-wide rows; a reach of every tenant leaves it alone.
     *
     * @template TQuery of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  TQuery  $query
     * @param  string  $table
     * @return TQuery
     */
    public function constrain(Builder $query, string $table): Builder
    {
        $tenants = $this->tenants;

        if ($tenants === null) {
            return $query;
        }

        $query->where(static function (Builder $query) use ($table, $tenants): void {
            $query->whereNull($table . '.tenant_type');

            foreach ($tenants as [$type, $ids]) {
                $query->orWhere(static fn (Builder $row): Builder => $row->where($table . '.tenant_type', $type)->whereIn($table . '.tenant_id', $ids));
            }
        });

        return $query;
    }

    /**
     * Return the tenants below the tenant, as the tree's subtree query selects
     * them, the tenant itself among them when the query selects it; for a flat
     * tree, none, without a query, since the tenant's chain already holds the
     * tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Contracts\TenantTree  $tree
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     *
     * @throws \UnexpectedValueException
     */
    private static function below(Reference $tenant, TenantTree $tree): array
    {
        if ($tree instanceof FlatTenantTree) {
            return [];
        }

        $subtree = $tree->subtree($tenant);
        $query   = $subtree instanceof EloquentBuilder ? $subtree->toBase() : $subtree;

        if (!$query instanceof QueryBuilder) {
            throw new \UnexpectedValueException('The tenant tree\'s subtree is not a query.');
        }

        $below = [];

        foreach ($query->get() as $row) {
            /** @var array{tenant_type: int|string, tenant_id: int|string} $columns */
            $columns = (array) $row;
            $below[] = new Reference((string) $columns['tenant_type'], (string) $columns['tenant_id']);
        }

        return $below;
    }
}
