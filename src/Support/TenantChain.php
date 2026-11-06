<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Container\Container;
use Illuminate\Contracts\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;

/**
 * A tenant and its ancestors, nearest first, as the bound tenant tree answers
 * them: the tenants whose records a tenant sees and whose grants reach it
 * (AUTHZ-5.3).
 *
 * An empty chain is the platform: no tenant, so only platform-wide records and
 * grants count (AUTHZ-5.7).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TenantChain
{
    /**
     * Create a new tenant chain.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $tenants
     */
    public function __construct(

        /** The tenant first, then its ancestors, nearest first; none for the platform. */
        public array $tenants = [],
    ) {}

    /**
     * Return the chain of the tenant through the given tree, or the platform's
     * for no tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \SineMacula\Laravel\Authorization\Contracts\TenantTree  $tree
     * @return self
     */
    public static function of(?Reference $tenant, TenantTree $tree): self
    {
        return $tenant === null ? new self : new self([$tenant, ...$tree->ancestors($tenant)]);
    }

    /**
     * Determine whether the tenant is the ancestor or below it in the bound
     * tree. The platform is within no tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @return bool
     */
    public static function isWithin(?Reference $tenant, Reference $ancestor): bool
    {
        return $tenant !== null && self::tree()->isWithin($tenant, $ancestor);
    }

    /**
     * Return the bound tenant tree.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\TenantTree
     */
    public static function tree(): TenantTree
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\TenantTree */
        return Container::getInstance()->make(TenantTree::class);
    }

    /**
     * Limit the query to the records the chain's tenant sees: the platform's,
     * and those of the tenant and its ancestors.
     *
     * @template TQuery of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  TQuery  $query
     * @param  string  $typeColumn
     * @param  string  $idColumn
     * @return TQuery
     */
    public function owners(Builder $query, string $typeColumn, string $idColumn): Builder
    {
        $query->where(function (Builder $query) use ($typeColumn, $idColumn): void {
            $query->whereNull($typeColumn);

            foreach ($this->tenants as $tenant) {
                $query->orWhere(static function (Builder $query) use ($typeColumn, $idColumn, $tenant): void {
                    $query->where($typeColumn, $tenant->type)->where($idColumn, $tenant->id);
                });
            }
        });

        return $query;
    }

    /**
     * Limit a grant query to the grants that hold in the chain's tenant:
     * platform-wide grants, the tenant's own, and its ancestors' that reach the
     * tenants below them.
     *
     * @template TQuery of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  TQuery  $query
     * @param  string  $table
     * @return TQuery
     */
    public function grants(Builder $query, string $table): Builder
    {
        $query->where(function (Builder $query) use ($table): void {
            $query->whereNull($table . '.tenant_type');

            foreach ($this->tenants as $depth => $tenant) {
                $query->orWhere(static function (Builder $query) use ($table, $tenant, $depth): void {
                    self::heldIn($query, $table, $tenant, $depth === 0);
                });
            }
        });

        return $query;
    }

    /**
     * Order the query's records nearest owner first: the tenant's, then each
     * ancestor's in turn, then the platform's. The platform's chain sees only
     * the platform's records, so it leaves the order alone. The owner columns
     * are given wrapped by the grammar, since they are written into the
     * expression as they are.
     *
     * @template TQuery of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  TQuery  $query
     * @param  string  $typeColumn
     * @param  string  $idColumn
     * @return TQuery
     */
    public function nearestFirst(Builder $query, string $typeColumn, string $idColumn): Builder
    {
        if ($this->tenants === []) {
            return $query;
        }

        $cases    = '';
        $bindings = [];

        foreach ($this->tenants as $depth => $tenant) {
            $cases .= " when {$typeColumn} = ? and {$idColumn} = ? then {$depth}";

            \array_push($bindings, $tenant->type, $tenant->id);
        }

        $query->orderByRaw('case' . $cases . ' else ' . \count($this->tenants) . ' end', $bindings);

        return $query;
    }

    /**
     * Return the tenant the chain starts at, or null for the platform.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    public function tenant(): ?Reference
    {
        return $this->tenants[0] ?? null;
    }

    /**
     * Limit a grant query to the grants made in the tenant: all of them in the
     * chain's own tenant, and in an ancestor only those that reach the tenants
     * below it.
     *
     * @param  \Illuminate\Contracts\Database\Query\Builder  $query
     * @param  string  $table
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  bool  $own
     * @return void
     */
    private static function heldIn(Builder $query, string $table, Reference $tenant, bool $own): void
    {
        $query->where($table . '.tenant_type', $tenant->type)->where($table . '.tenant_id', $tenant->id);

        if ($own) {
            return;
        }

        $query->where($table . '.include_subtree', true);
    }
}
