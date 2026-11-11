<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Container\Container;
use Illuminate\Contracts\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Database\ComposedExpression;

/**
 * A tenant and its ancestors, nearest first, as the bound tenant tree answers
 * them: the tenants whose records a tenant sees and whose grants reach it
 * (AUTHZ-5.3).
 *
 * An empty chain is the platform: no tenant, so only platform-wide records and
 * grants count (AUTHZ-5.7). A row is the platform's only when both its tenant
 * columns are null (see `whereNullTenant()`): a row naming half a tenant, a
 * type without a key or a key without a type, which the package never writes,
 * is neither the platform's nor any tenant's, so no chain reads it, and as a
 * grant or an owner it applies nowhere; what restricts of it applies everywhere
 * instead, read through `TenantColumns` (N130).
 *
 * A chain may stand just below its tenant: a grant made in the tenant then
 * counts only when it reaches the tenants below it, as an ancestor's does, so
 * what holds there is what holds in every one of the tenant's children from
 * above them. A guardrail on a tenant is changed from there (AUTHZ-7.6): from
 * the scope of the tenant's parent, by a grant that reaches the tenant, never
 * one made in the tenant itself.
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
     * @param  bool  $isBelow
     */
    public function __construct(

        /** The tenant first, then its ancestors, nearest first; none for the platform. */
        public array $tenants = [],

        /** Whether the chain stands just below its tenant, so a grant made there counts only when it reaches below. */
        public bool $isBelow = false,
    ) {}

    /**
     * Return the chain of the tenant through the given tree, standing just
     * below the tenant when asked, or the platform's for no tenant.
     *
     * While a batch of checks is open, the tree is asked for a tenant's
     * ancestors once (see `ResolutionCache::answerTree()`), unless they are
     * read afresh, which replaces the answer kept.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \SineMacula\Laravel\Authorization\Contracts\TenantTree  $tree
     * @param  bool  $isBelow
     * @param  bool  $isFresh
     * @return self
     */
    public static function of(?Reference $tenant, TenantTree $tree, bool $isBelow = false, bool $isFresh = false): self
    {
        if ($tenant === null) {
            return new self;
        }

        $ancestors = static fn (): array => $tree->ancestors($tenant);
        $cache     = ResolutionCache::instance();

        /** @var list<\SineMacula\Laravel\Authorization\Support\Reference> $read */
        $read = $cache === null ? $ancestors() : $cache->answerTree(['ancestors', (string) \spl_object_id($tree), $tenant->type, $tenant->id], $ancestors, $isFresh);

        return new self([$tenant, ...$read], $isBelow);
    }

    /**
     * Determine whether the tenant is the ancestor or below it in the bound
     * tree. The platform is within no tenant. While a batch of checks is open,
     * the tree is asked about each pair of tenants once.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @return bool
     */
    public static function isWithin(?Reference $tenant, Reference $ancestor): bool
    {
        if ($tenant === null) {
            return false;
        }

        $tree     = self::tree();
        $isWithin = static fn (): bool => $tree->isWithin($tenant, $ancestor);
        $cache    = ResolutionCache::instance();

        $question = ['within', (string) \spl_object_id($tree), $tenant->type, $tenant->id, $ancestor->type, $ancestor->id];

        return $cache === null ? $isWithin() : $cache->answerTree($question, $isWithin);
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
     * Limit the query to the rows of the platform: those whose tenant columns
     * are both null. A row naming half a tenant is never the platform's, so it
     * is left out, as every tenant's chain leaves it out too.
     *
     * @template TQuery of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  TQuery  $query
     * @param  string  $typeColumn
     * @param  string  $idColumn
     * @return TQuery
     */
    public static function whereNullTenant(Builder $query, string $typeColumn, string $idColumn): Builder
    {
        $query->whereNull($typeColumn)->whereNull($idColumn);

        return $query;
    }

    /**
     * Limit the query to the records the chain's tenant sees: the platform's,
     * and those of the tenant and its ancestors; a record naming half a tenant
     * is seen by none.
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
            self::whereNullTenant($query, $typeColumn, $idColumn);

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
     * tenants below them; for a chain standing just below its tenant, the
     * tenant's own only when they reach below it too. A grant naming half a
     * tenant holds in none; a reader of what restricts adds such rows through
     * `TenantColumns::restricting()` or `attachments()`.
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
            self::whereNullTenant($query, $table . '.tenant_type', $table . '.tenant_id');

            foreach ($this->tenants as $depth => $tenant) {
                $own = $depth === 0 && !$this->isBelow;

                $query->orWhere(static function (Builder $query) use ($table, $tenant, $own): void {
                    self::heldIn($query, $table, $tenant, $own);
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

        $query->orderBy(new ComposedExpression('case' . $cases . ' else ' . \count($this->tenants) . ' end'));
        $query->addBinding($bindings, 'order');

        return $query;
    }

    /**
     * Determine whether the other chain lists the same tenants in the same
     * order, standing where this one does.
     *
     * @param  self  $other
     * @return bool
     */
    public function isSameAs(self $other): bool
    {
        return self::pairs($this->tenants) === self::pairs($other->tenants) && $this->isBelow === $other->isBelow;
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
     * Determine whether the chain starts at the tenant: a check decided in it
     * is decided in that tenant. The platform's chain starts at no tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return bool
     */
    public function isAt(Reference $tenant): bool
    {
        $own = $this->tenant();

        return $own !== null && $own->type === $tenant->type && $own->id === $tenant->id;
    }

    /**
     * Return each tenant as its type and key.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $tenants
     * @return list<array{0: string, 1: string}>
     */
    private static function pairs(array $tenants): array
    {
        return \array_map(static fn (Reference $tenant): array => [$tenant->type, $tenant->id], $tenants);
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
